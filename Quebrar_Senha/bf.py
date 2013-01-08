#!/usr/bin/python
#coding: utf-8
'''
Script que testa senha fracas em um ambiente. Ele testa senha númericas de 1 a 6 digitos.
'''

from crypt import crypt
from multiprocessing import Process, cpu_count, Queue, Manager
import hashlib
import time
import re

dicpwd = dict()
procs = cpu_count()
possibles = Queue()


def pwd_parser():
    '''
    Gera um dicionário com usuário e senha do arquivo shadow
    '''
    pwd = dict()
    try: 
       #Separando o nome do usuario com a senha criptografada.
       for linha in open('shadow','r').readlines():
          if linha.split(':')[1].startswith('$'):
             pwd[linha.split(':')[0]] = linha.split(':')[1]
       return pwd
    except:
       return False

def generate(q):
    '''
    Função que insere em uma fila as senhas do arquivo passwords.txt
    '''
    f = open('passwords.txt','r')
    for senha in f.read().split():
       q.put(senha)
    for x in range(1,procs+1):
       q.put(None)
        
def consume(q, pwd):
    '''
    Função dos trabalhadores que consomem a fila de senhas possíveis geradas pela função generate
    '''
    c = ''
    while c != None:
        if not q.empty():            
            c = q.get()
            verify(c, pwd )
            if len(pwd) == 0 :
                break

def verify(cand, pwd):
    '''
    Função que verifica se a senha candidata conferi com o hash.
    '''
    for user,password in pwd.items():
        if password == crypt(cand,re.search(r'^\$.\$.+\$',password).group()):
            print 'Encontrada a senha do usuário {}: {}'.format(user, cand)
            pwd.pop(user)
            
       
def principal():
    mgr = Manager()    
    dicpwd = mgr.dict(pwd_parser())

    if not dicpwd:
        print 'Você não possui os privilégios necessários para a resolução do problema'
    else:
       # Inicia um processo que gerará as senhas possiveis segundo os parametros informados
       p = Process(target=generate, args=(possibles,))
       p.daemon = True
       p.start()
       time.sleep(3)
       for x in range(1, procs+1):
           o = Process(target=consume, args=(possibles,dicpwd))
           o.daemon = True
           o.start()
       for x in range(1, procs+1):
           o.join()
       p.terminate()
         
if __name__ == '__main__':
    principal()
