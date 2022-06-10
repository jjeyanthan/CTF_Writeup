

def tour2(password):
    new = []
    i = 0
    while password != []:
        new.append(password[password.index(password[i])])
        new.append(password[password.index(password[i])] + password[password.index(password[ i + 1 %len(password)])])
        password.pop(password.index(password[i]))
        i += int('qkdj', base=27) - int('QKDJ', base=31) + 267500
    return new


## resultat evolue des deux sens  en meme temps
def tour3(password):  
    mdp =['l', 'x', 'i', 'b', 'i', 'i', 'q', 'u', 'd', 'v', 'a', 'v', 'b', 'n', 'l', 'v', 'v', 'l', 'g', 'z', 'q', 'g', 'i', 'u', 'd', 'u', 'd', 'j', 'o', 'r', 'y', 'r', 'u', 'a']

    for i in range(len(password)):
        mdp[i], mdp[len(password) - i -1 ] = chr(password[len(password) - i -1 ] + i % 4),  chr(password[i] + i % 4)
    return "".join(mdp)

# tour2 max 17   -> 17*2 = 34
# tour3 max = 34 en entre


 
def brute_force():
    secret = "¡P6¨sÉU1T0d¸VÊvçu©6RÈx¨4xFw5"

    flag=""

    third_cycle=[]

    zeros = [0 for z in range(34)]
    for i in range(len(secret)):
        for j in range(255):
            zeros = [ j  for z in range(34)]
            result = tour3((zeros))
            if result[i] == secret[i]:
                third_cycle.append(j)
                
              
                
   #print(third_cycle[::-1])

    encrypted= third_cycle[::-1]
    p=0
    second_cycle=[0 for i in range(17)]
    for x in range(0,len(encrypted),2):
        second_cycle[p] = encrypted[x]
        p+=1

    tour1_rep = second_cycle[::-1]
    
    for s in tour1_rep:
        flag+=chr(s)

    print(flag)  
 



brute_force()

# 404CTF{P4sS1R0bUst3Qu3C4}
