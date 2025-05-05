from itertools import product
from typing import Tuple, List
from math import sqrt, sqrt
import socket
from pwn import *
import re
import numpy as np

# Adresse et port du serveur Netcat
HOST = 'chall.fcsc.fr' 
PORT = 2054   

CUBE_SIZE = 32

# Define adjacent faces
ADJACENT = {
    'x0': ['y0', 'y1', 'z0', 'z1'],
    'x1': ['y0', 'y1', 'z0', 'z1'],
    'y0': ['x0', 'x1', 'z0', 'z1'],
    'y1': ['x0', 'x1', 'z0', 'z1'],
    'z0': ['x0', 'x1', 'y0', 'y1'],
    'z1': ['x0', 'x1', 'y0', 'y1'],
}

def points_I_sur_bord(A, face_A):
    """Renvoie la liste des points I (x,y,z, d2) pour un point A donné."""
    xA, yA, zA = A
    face_coord = None            # quelle coordonnée est figée ?
    if 'x' in face_A:
        face_coord = 'x'
    elif 'y' in face_A:
        face_coord = 'y'
    elif 'z' in face_A:
        face_coord = 'z'
    else:
        raise ValueError("A n'est pas sur la bordure du cube.")

    I_points = []
    fixed = (0, CUBE_SIZE)          # valeurs possibles pour les coord. fixées

    if face_coord == 'x':
        x = xA                   # arêtes : x fixe
        for y_fixed in fixed:
            for z in range(CUBE_SIZE + 1):
                I_points.append((x, y_fixed, z))
        for z_fixed in fixed:
            for y in range(CUBE_SIZE + 1):
                I_points.append((x, y, z_fixed))

    elif face_coord == 'y':
        y = yA
        for x_fixed in fixed:
            for z in range(CUBE_SIZE + 1):
                I_points.append((x_fixed, y, z))
        for z_fixed in fixed:
            for x in range(CUBE_SIZE + 1):
                I_points.append((x, y, z_fixed))

    else:  # face_coord == 'z'
        z = zA
        for x_fixed in fixed:
            for y in range(CUBE_SIZE + 1):
                I_points.append((x_fixed, y, z))
        for y_fixed in fixed:
            for x in range(CUBE_SIZE + 1):
                I_points.append((x, y_fixed, z))

    # enlever les doublons (les sommets) et calculer d²
    uniques = {(x, y, z) for (x, y, z) in I_points}
    resultats = []
    for (x, y, z) in uniques:
        d2 = (xA - x)**2 + (yA - y)**2 + (zA - z)**2
        resultats.append((x, y, z, d2))

    return resultats              # ~128 quadruplets (x,y,z,d2)

    
def points_I_adjacents(face_A):
    """Renvoie la liste des points I (x,y,z) des faces adjacentes à une face données : les artes perpendiculaires à la face"""
    face_coord = None            # quelle coordonnée varie sur la perpendiculaire ?
    if 'x' in face_A:
        face_coord = 'x'
    elif 'y' in face_A:
        face_coord = 'y'
    elif 'z' in face_A:
        face_coord = 'z'
    else:
        raise ValueError("Face inexistante: ", face_A)

    I_points = []

    if face_coord == 'x':
        for x in np.arange(1, CUBE_SIZE - 1, 0.5):
            I_points.append((x, 0, 0))
            I_points.append((x, 0, CUBE_SIZE))
            I_points.append((x, CUBE_SIZE, 0))
            I_points.append((x, CUBE_SIZE, CUBE_SIZE))
    elif face_coord == 'y':
        for y in np.arange(1, CUBE_SIZE - 1, 0.5):
            I_points.append((0, y, 0))
            I_points.append((0, y, CUBE_SIZE))
            I_points.append((CUBE_SIZE, y, 0))
            I_points.append((CUBE_SIZE, y, CUBE_SIZE))
    else:  # face_coord == 'z'
        for z in np.arange(1, CUBE_SIZE - 1, 0.5):
            I_points.append((0, 0, z))
            I_points.append((0, CUBE_SIZE, z))
            I_points.append((CUBE_SIZE, 0, z))
            I_points.append((CUBE_SIZE, CUBE_SIZE, z))

    return I_points              

    
def points_I_detail(A, I, face_A):
    """Renvoie la liste des points I (x,y,z, d2) pour un point A donné."""
    step = 10
    xA, yA, zA = A
    xI, yI, zI =I
    coord_change = None            # quelle coordonnée est figée ?
    if 'x' in face_A:
        if yI == 0 or yI == 32:
            coord_change = 'z'
        else:
            coord_change = 'y'
    elif 'y' in face_A:
        if zI == 0 or zI == 32:
            coord_change = 'x'
        else:
            coord_change = 'z'
    elif 'z' in face_A:
        if xI == 0 or xI == 32:
            coord_change = 'y'
        else:
            coord_change = 'x'
    else:
        raise ValueError("A n'est pas sur la bordure du cube.")

    I_points = []
 
    for i in range (-step, step+1):
        if coord_change == 'x':
            I_points.append((xI + (i / step) * 1.0, yI, zI))
        if coord_change == 'y':
            I_points.append((xI, yI + (i / step) * 1.0, zI))
        if coord_change == 'z':
            I_points.append((xI, yI, zI + (i / step) * 1.0))
    resultats = []
    # enlever les doublons (les sommets) et calculer d²
    for (x, y, z) in I_points:
        d2 = (xA - x)**2 + (yA - y)**2 + (zA - z)**2
        resultats.append((x, y, z, d2))

    return resultats          

# best= le meilleur connu jusqu'ici
def meilleurs_points_communs(liste_A, liste_B, liste_adjacent, best):
    d2A = {(x, y, z): d2 for (x, y, z, d2) in liste_A}
    d2B = {(x, y, z): d2 for (x, y, z, d2) in liste_B}

    candidats = []
   ## cas 2 : AI + IB
    for (x, y, z, d2b) in liste_B:
        # ignorer si db2 deja trop
        if d2b < best and (x, y, z) in d2A:
            d2a = d2A[(x, y, z)]
            # ignorer si da2 deja trop
            # print("pt= ", (x,y,z))
            if d2a < best:
                # somme des longueurs (entière) = racine entière de chaque carré
                score = sqrt(d2a) + sqrt(d2b)
                score2 = score**2
                if score2 < best:
                    # print("got new record for ",x,",", y,",", z, " with :" , score2)
                    best = score2
                    candidats.append((score, x, y, z, -1, -1, -1,-1, -1, -1, d2a, d2b, -1, -1))
    ## cas 3 ou cas 4 plus complexe : on fait A --> I1 --> I2 --B  (jamais plus et seulement si i1 et i2 sont sur la meme face)
    for (xb, yb, zb, d2b) in liste_B:
        # ignorer si db2 deja trop
        if d2b < best and not (xb, yb, zb) in d2A:
            for (xa, ya, za, d2a) in liste_A:
                d2a = d2A[(xa, ya, za)]     
                if d2a < best and not (xa, ya, za) in d2B and share_one_face((xa, ya, za), (xb, yb, zb)):
                    d_inter2 = d2_same_face((xa, ya, za), (xb, yb, zb))
                    # ignorer si da2 deja trop
                    if d_inter2 < best:
                        score = sqrt(d2a) + sqrt(d_inter2) + sqrt(d2b)
                        score2 = score**2
                        if score2 < best:
                            best = score2
                            candidats.append((score, xa, ya, za, xb, yb, zb, -1, -1, -1, d2a, d2b, d_inter2, -1))
    
    if liste_adjacent != None:
        # cas 5: essayer de passer par les segemnts adjacents à 2 faces opposées
        print("Use adjacent")
        count = 0
        for (xb, yb, zb, d2b) in liste_B:
            # ignorer si db2 deja trop
            if d2b < best:
                for (xI, yI, zI) in liste_adjacent:
                    if share_one_face( (xb, yb, zb), (xI, yI, zI)):
                        # on va jusqu'à un I sur coté adjacent : mais sans passer "dans le cube" : on reste du des sements de eme face
                        d_inter2 = d2_same_face( (xb, yb, zb), (xI, yI, zI))
                        if d_inter2 < best:
                            scoreB_to_I = sqrt(d_inter2) + sqrt(d2b)
                            if scoreB_to_I**2 < best:
                                # on continue vers un point de face_A (sans traverser le cube)
                                for (xa, ya, za, d2a) in liste_A:
                                    if share_one_face( (xa, ya, za), (xI, yI, zI)):
                                        #count = count + 1
                                        #if count > 10:
                                        #    break
                                        #print("B  try ", (xb, yb, zb), "  -> ", (xI, yI, zI), "  -> ",(xa, ya, za))

                                        d2a = d2A[(xa, ya, za)]     
                                        d_inter3 = d2_same_face( (xa, ya, za), (xI, yI, zI))
                                        score = sqrt(d2a) + sqrt(d_inter3) + scoreB_to_I
                                        score2 = score**2
                                        if score2 < best:
                                            best = score2
                                            #print("** CHEMIN : I1=",  (xa, ya, za), " I2=", (xI, yI, zI), " I3=", (xb, yb, zb), " score ", score2)
                                            candidats.append((score, xa, ya, za, xb, yb, zb,  xI, yI, zI, d2a, d2b, d_inter2, d_inter3))


    print (f"{len(candidats)} candidats best: {best}" )
    # tri naturel sur 'score' puis retourne le meilleurs
    n = 1
    #print("best :", best)
    #print("I= ", [(xa, ya, za) for (score, xa, ya, za, xb, yb, zb, d2a, d2b, d_inter2) in sorted(candidats)[:5]])
    return sorted(candidats)[:n]            

def list_faces(p: Tuple[int, int, int]):
    l = []
    x, y, z = p
    if x == 0:
        l.append('x0')
    if x == CUBE_SIZE:
        l.append( 'x1')
    if y == 0:
        l.append( 'y0')
    if y == CUBE_SIZE:
        l.append( 'y1')
    if z == 0:
        l.append( 'z0')
    if z == CUBE_SIZE:
        l.append( 'z1')
    return l

def share_one_face(A, B):
    return bool(set(list_faces(A)) & set(list_faces(B)))
def d2_same_face(A, B):
    # la coordonnée commune vaut 0 ou 32, donc la différence est nulle
    return (A[0] - B[0])**2 + (A[1] - B[1])**2 + (A[2] - B[2])**2

def all_faces_dist(A, B):
    faces_A = list_faces(A)
    print("Faces de A", faces_A)
    faces_B = list_faces(B)
    print("Faces de B", faces_B)
    if share_one_face(A,B):
        # same face
        print("Same face")
        return d2_same_face(A,B)
    adjacent = False
    for face_A in faces_A:
        for face_B in faces_B:
            if face_B in ADJACENT[face_A]:
                adjacent = True
    if adjacent:
        print("Adjacent face")
    else:
        print("Opposite face")

    min_dist = math.inf
    for face_A in faces_A:
        for face_B in faces_B:
            liste_A = points_I_sur_bord(A, face_A)
            liste_B = points_I_sur_bord(B, face_B)
            liste_adjacent = None
            if not adjacent:
                liste_adjacent = points_I_adjacents(face_A)
            best = math.inf
            top2 = meilleurs_points_communs(liste_A, liste_B, liste_adjacent, best)
            for s, xa, ya, za, xb, yb, zb, xI, yI, zI, d2a, d2b, d_inter2, d_inter3 in top2:
                s2 = s **2
                if xb < 0:
                    # en un Point de bordure
                    print(f"I=({xa},{ya},{za})  |AI|≈{sqrt(d2a)}  |IB|≈{sqrt(d2b)}  somme2≈{s*s}")
                    liste_A_detail = points_I_detail(A, (xa, ya, za), face_A)
                    for (xi, yi, zi, d2a) in liste_A_detail:
                        d2b = d2_same_face((xi, yi, zi), B)
                        score = sqrt(d2b) + sqrt(d2a)
                        score2 = score**2
                        if score2 < min_dist:
                            min_dist = score2
                            #print(f"DETAIL - 1stCase - One I : I=({xi},{yi},{zi})  |AI|≈{sqrt(d2a)}  |IB|≈{sqrt(d2b)}  somme2≈{score2}")
                elif xI < 0:
                    # en 2 Points de bordure
                    print(f"I1=({xa}, {ya}, {za}) I2=({xb},{yb},{zb})  |AI1|≈{sqrt(d2a)} |I1I2|≈{sqrt(d_inter2)} |I2B|≈{sqrt(d2b)}  somme2≈{s*s}")
                    liste_A_detail = points_I_detail(A, (xa, ya, za), face_A)
                    liste_B_detail = points_I_detail(B, (xb, yb, zb), face_B)
                    #print("A: ", liste_A_detail)
                    #print("B: ", liste_B_detail)
                    top2_detail = meilleurs_points_communs(liste_A_detail, liste_B_detail, None, best)
                    for s, xa, ya, za, xb, yb, zb, xI, yI, zI, d2a, d2b, d_inter2,  d_inter3 in top2_detail:
                        s2 = s **2
                        #print(f"DETAIL - 2ndCase - Two I : I1=({xa}, {ya}, {za}) I2=({xb},{yb},{zb})  |AI1|≈{sqrt(d2a)} |I1I2|≈{sqrt(d_inter2)} |I2B|≈{sqrt(d2b)}  somme2≈{s*s}")
                        if s2 < min_dist:
                            min_dist = s2
                else:
                    # en 3 Points de bordure
                    print(f"I1=({xa}, {ya}, {za}) I2=({xI},{yI},{zI}) I3=({xb},{yb},{zb})  |AI1|≈{sqrt(d2a)} |I1I2|≈{sqrt(d_inter2)} |I2B|≈{sqrt(d2b)}  somme2≈{s*s}")
                    liste_A_detail = points_I_detail(A, (xa, ya, za), face_A)
                    liste_B_detail = points_I_detail(B, (xb, yb, zb), face_B)
                    #print("A: ", liste_A_detail)
                    #print("B: ", liste_B_detail)
                    top2_detail = meilleurs_points_communs(liste_A_detail, liste_B_detail, liste_adjacent, best)
                    for s, xa, ya, za, xb, yb, zb, xI, yI, zI, d2a, d2b, d_inter2,  d_inter3 in top2_detail:
                        s2 = s **2
                        #print(f"DETAIL - 2ndCase - Two I : I1=({xa}, {ya}, {za}) I2=({xI},{yI},{zI}) I3=({xb},{yb},{zb}) |AI1|≈{sqrt(d2a)} |I1I2|≈{sqrt(d_inter2)} |I2I3|≈{sqrt(d_inter3)} |I2B|≈{sqrt(d2b)}  somme2≈{s*s}")
                        if s2 < min_dist:
                            min_dist = s2
        
                if s2 < min_dist:
                    min_dist = s2
                
        
    return min_dist

def safe_round(x, epsilon=0.1):
    print(abs(x - round(x)), " is compared to ", epsilon)
    if abs(x - round(x)) < epsilon:
        print(" round ", x , " -> ", round(x))
        return round(x)
    return int(x)

needTest = False
if needTest:
    # ---------- Démonstration ----------
    #A = (5, 0, 29)
    #B = (1, 20, 32)
    #expected_distance = 305

    A = (0,2,14)
    B= (32,28,11)
    expected_distance = 3789

    #A = (8, 26, 32)
    #B = (11, 32, 28)
    #expected_distance = 109



    min_dist = all_faces_dist(A, B)
    print(f"distance2={min_dist} expected={expected_distance}" )

# Connexion
needAlice = True
if needAlice:
    conn = remote(HOST, PORT)
    try_nb = 0
    while True:
        try:
            # Lire Alice
            print(" ===== TryNb =", try_nb)
            try_nb += 1
            if needAlice:
                conn.recvuntil(b'Alice = ')
                alice_data = conn.recvline().decode().strip()
                print(f"[Server] {alice_data}")
                A = tuple(map(int, alice_data.strip('[]').split(',')))
            needAlice = True
            # Lire Bob
            conn.recvuntil(b'Bob   = ')
            bob_data = conn.recvline().decode().strip()
            print(f"[Server] {bob_data}")
            B = tuple(map(int, bob_data.strip('[]').split(',')))

            # Lire Distance:
            conn.recvuntil(b'Distance:')
            print("[Server] Distance:")

            # Calculer
            distance = all_faces_dist(A, B)
            print(f"[Client] Calculated Distance^2: {safe_round(distance)} ~ {distance}")

            # Envoyer la réponse
            conn.sendline(str(safe_round(distance)).encode())

            # 📢 Après l'envoi, on lit une nouvelle ligne
            next_line = conn.recvline().decode().strip()
            print(f"[Server reply or next] {next_line}")

            if "Alice =" in next_line:
                # C'est directement un nouvel énoncé ➔ remettre dans la boucle
                alice_data = next_line.split('=')[1].strip()
                A = tuple(map(int, alice_data.strip('[]').split(',')))
                print(f"     -------     ")
                print(f"[Server] New parsed Alice: {A}")
                needAlice = False
                continue  # on continue la boucle directement

            if 'Congrats' in next_line:
                print("🏴 FLAG found!")
                next_line = conn.recvline().decode().strip()
                print(f"[Server reply or next] {next_line}")
                next_line = conn.recvline().decode().strip()
                print(f"[Server reply or next] {next_line}")
                break

            if 'Wrong' in next_line or 'Erreur' in next_line:
                print("❌ Wrong answer... stopping.")
                break
            
        except EOFError:
            print("Connection closed by server.")
            print("TryNb =", try_nb)
            break

    conn.close()