def tour1(password):   # retourne le code ascii de chaque caractere du password dans ordre inverse
    string = str("".join( "".join(password[::-1])[::-1])[::-1])
    return [ord(c) for c in string]
## AABC
## CBAA
# retourne tableau 


def tour2(password):  # prend en entree tableau
    new = []
    i = 0
    while password != []:
        new.append(password[password.index(password[i])])
        new.append(password[password.index(password[i])] + password[password.index(password[ i + 1 %len(password)])])
        password.pop(password.index(password[i]))
        i += int('qkdj', base=27) - int('QKDJ', base=31) + 267500
    return new

# retourne un nouveau tableau avec [ el[i] ,  el[i]+ el[i+1] ,  ...]

def tour3(password):
    mdp =['l', 'x', 'i', 'b', 'i', 'i', 'q', 'u', 'd', 'v', 'a', 'v', 'b', 'n', 'l', 'v', 'v', 'l', 'g', 'z', 'q', 'g', 'i', 'u', 'd', 'u', 'd', 'j', 'o', 'r', 'y', 'r', 'u', 'a']
    for i in range(len(password)):
        mdp[i], mdp[len(password) - i -1 ] = chr(password[len(password) - i -1 ] + i % 4),  chr(password[i] + i % 4)
    return "".join(mdp)


# password  de 37 caracteres

mdp = input("Mot de passe : ")

if tour3(tour2(tour1(mdp))) == "¡P6¨sÉU1T0d¸VÊvçu©6RÈx¨4xFw5":
    print("Bravo ! Le flag est 404CTF{" + mdp + "}")
else :
    print("Désolé, le mot-de-passe n'est pas correct")




