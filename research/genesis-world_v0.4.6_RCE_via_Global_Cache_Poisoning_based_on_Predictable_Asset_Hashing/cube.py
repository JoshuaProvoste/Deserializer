import trimesh
import numpy as np

# Geometría idéntica a la usada en el Paso 1
verts = np.array([[0,0,0],[1,0,0],[1,1,0],[0,1,0],[0,0,1],[1,0,1],[1,1,1],[0,1,1]], dtype=np.float32)
faces = np.array([[0,1,2],[0,2,3],[4,5,6],[4,6,7],[0,4,7],[0,7,3],[1,5,6],[1,6,2],[0,1,5],[0,5,4],[2,3,7],[2,7,6]], dtype=np.int32)

# IMPORTANTE: process=False para evitar que trimesh altere la geometría
mesh = trimesh.Trimesh(vertices=verts, faces=faces, process=False)
mesh.export('cube.obj')
print("[*] Archivo cube.obj generado con éxito.")