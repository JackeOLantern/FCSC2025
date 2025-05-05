from typing import Tuple, List
import socket
from pwn import *
import re

CUBE_SIZE = 32


# Adresse et port du serveur Netcat
HOST = 'chall.fcsc.fr' 
PORT = 2054   

def parse_point(line: str):
    """Extrait un point [x,y,z] depuis une ligne de texte."""
    nums = list(map(int, re.findall(r'\d+', line)))
    return tuple(nums)

# Define faces
FACES = ['x0', 'x1', 'y0', 'y1', 'z0', 'z1']

# Define adjacent faces
ADJACENT = {
    'x0': ['y0', 'y1', 'z0', 'z1'],
    'x1': ['y0', 'y1', 'z0', 'z1'],
    'y0': ['x0', 'x1', 'z0', 'z1'],
    'y1': ['x0', 'x1', 'z0', 'z1'],
    'z0': ['x0', 'x1', 'y0', 'y1'],
    'z1': ['x0', 'x1', 'y0', 'y1'],
}

# Get face of a point
def get_face(p: Tuple[int, int, int]) -> str:
    x, y, z = p
    if x == 0:
        return 'x0'
    if x == CUBE_SIZE:
        return 'x1'
    if y == 0:
        return 'y0'
    if y == CUBE_SIZE:
        return 'y1'
    if z == 0:
        return 'z0'
    if z == CUBE_SIZE:
        return 'z1'
    raise ValueError(f"Point {p} is not on a cube face")

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

# Project 3D point onto 2D coordinates of a given face
def project_on_face(p: Tuple[int, int, int], face: str) -> Tuple[int, int]:
    x, y, z = p
    if face == 'x0' or face == 'x1':
        return (y, z)
    if face == 'y0' or face == 'y1':
        return (x, z)
    if face == 'z0' or face == 'z1':
        return (x, y)
    raise ValueError(f"Unknown face {face}")

# Distance squared
def dist2(p1: Tuple[float, float], p2: Tuple[float, float]) -> float:
    return (p1[0] - p2[0])**2 + (p1[1] - p2[1])**2

# Define transformations for unfolding cible
TRANSFORM = {
    ('x0', 'y0'): lambda x, y: (-x, y), # OK 
    ('x0', 'y1'): lambda x, y: (CUBE_SIZE + x, y), # OK 
    ('x0', 'z0'): lambda x, y: (y, -x), # OK
    ('x0', 'z1'): lambda x, y: ( y, CUBE_SIZE + x),# OK

    ('x1', 'y0'): lambda x, y: (x -CUBE_SIZE, y) , # ok
    ('x1', 'y1'): lambda x, y: (CUBE_SIZE + CUBE_SIZE - x, y), # ok
    ('x1', 'z0'): lambda x, y: (y, x - CUBE_SIZE), # ok?
    ('x1', 'z1'): lambda x, y: (y, CUBE_SIZE + CUBE_SIZE -x),

    ('y0', 'x0'): lambda x, y: (-x, y),
    ('y0', 'x1'): lambda x, y: (CUBE_SIZE + x, y),
    ('y0', 'z0'): lambda x, y: (x, -y),# OK?
    ('y0', 'z1'): lambda x, y: (x, CUBE_SIZE + y),
# --
    ('y1', 'x0'): lambda x, y: (x - CUBE_SIZE, y),
    ('y1', 'x1'): lambda x, y: (CUBE_SIZE + CUBE_SIZE - x, y),
    ('y1', 'z0'): lambda x, y: (x, -y),
    ('y1', 'z1'): lambda x, y: (x, CUBE_SIZE + CUBE_SIZE - y),

    ('z0', 'x0'): lambda x, y: (-y, x),
    ('z0', 'x1'): lambda x, y: (CUBE_SIZE + y, x),
    ('z0', 'y0'): lambda x, y: (x, -y),
    ('z0', 'y1'): lambda x, y: (x, CUBE_SIZE + y), # OK?

    ('z1', 'x0'): lambda x, y: (y - CUBE_SIZE, x),
    ('z1', 'x1'): lambda x, y: (CUBE_SIZE + CUBE_SIZE - y, x),
    ('z1', 'y0'): lambda x, y: (x, y - CUBE_SIZE),
    ('z1', 'y1'): lambda x, y: (x, CUBE_SIZE + CUBE_SIZE - y),
}

# Main function
def minimal_face_distance_squared(A: Tuple[int, int, int], B: Tuple[int, int, int], face_A, face_B) -> float:
    proj_A = project_on_face(A, face_A)
    proj_B = project_on_face(B, face_B)
    print("A face: ", face_A, " proj: ", proj_A)
    if face_A == face_B:
        print("B same face: ", face_B, " proj: ", proj_B)
        return dist2(proj_A, proj_B)

    if face_B in ADJACENT[face_A]:
        transform = TRANSFORM[(face_A, face_B)]
        proj_B_adj = transform(*proj_B)
        print("B adj face: ", face_B, " proj: ", proj_B, " --> ", proj_B_adj)
        return dist2(proj_A, proj_B_adj)

    # Opposite faces: try all adjacent unfoldings
    min_dist = float('inf')
    for inter_face in ADJACENT[face_A]:
        if (face_A, inter_face) not in TRANSFORM:
            continue
        if (inter_face, face_B) not in TRANSFORM:
            continue
        transform1 = TRANSFORM[(face_A, inter_face)]
        transform2 = TRANSFORM[(inter_face, face_B)]

        temp_proj_B1 = transform2(*proj_B)
        temp_proj_B = transform1(*temp_proj_B1)
        print("B opp face: ", face_B, " proj: ", proj_B, " --> ", temp_proj_B1, " --> ", temp_proj_B)

        d = dist2(proj_A, temp_proj_B)
        if d < min_dist:
            min_dist = d

    return min_dist

def all_faces_dist(A, B):
    faces_A = list_faces(A)
    faces_B = list_faces(B)
    min = math.inf
    for face_A in faces_A:
        for face_B in faces_B:
            dist = minimal_face_distance_squared(A, B, face_A, face_B)
            print("for faceA=", face_A, " faceB=", face_B, " got :", dist)
            if (dist < min):
                min = dist

    return min
# Example usage
#A = (0, 2, 14)
#B = (32, 28, 11)
needTest = True
if needTest:
    A= (30, 1, 0)
    B= [23, 32, 4]

    print("A = ", A)
    print("B = ", B)
    minimal_distance_squared = all_faces_dist(A, B)
    print("distance=", minimal_distance_squared)
    print(f"Start cube ***************")

# Connexion
needAlice = False
if needAlice:
    conn = remote(HOST, PORT)
    try_nb = 0
    while True:
        try:
            # Lire Alice
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
            print(f"[Client] Calculated Distance^2: {distance}")

            # Envoyer la réponse
            conn.sendline(str(int(distance)).encode())

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

            if 'FCSC{' in next_line:
                print("🏴 FLAG found!")
                break

            if 'Wrong' in next_line or 'Erreur' in next_line:
                print("❌ Wrong answer... stopping.")
                break
            
        except EOFError:
            print("Connection closed by server.")
            print("TryNb =", try_nb)
            break

    conn.close()