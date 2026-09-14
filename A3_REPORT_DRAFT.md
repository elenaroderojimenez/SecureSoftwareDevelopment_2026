# A.3 Proteccion de las APIs web desarrolladas con Flask

## Contexto y alcance

El caso de estudio es una aplicacion web de gestion privada de archivos. Cada
persona usuaria puede crear una cuenta, iniciar sesion, subir documentos y
descargar exclusivamente los archivos que le pertenecen. La aplicacion se ha
desarrollado con Flask y SQLite para el contexto academico local. Su objetivo de
seguridad es proteger las credenciales, impedir el acceso anonimo a los recursos
privados, limitar ataques de fuerza bruta y evitar que un usuario descargue los
archivos de otro.

La aplicacion sigue una organizacion MVC ligera. Los modelos contienen las
consultas a SQLite (`application/models`), los controladores procesan las rutas
de Flask y aplican las reglas de seguridad (`application/controllers`) y las
plantillas HTML son la vista (`templates`). Esta separacion hace que los
controladores no construyan consultas SQL directamente y concentra el acceso a
datos en los modelos. Todas las consultas que reciben datos del usuario emplean
parametros de SQLite, por ejemplo `WHERE username = ?`, en lugar de concatenar
la entrada en una consulta.

Los recursos privados se protegen con una sesion de Flask. Tras una
autenticacion correcta, la sesion contiene el estado de inicio de sesion, el
nombre de usuario y una version de sesion. El decorador `login_required` valida
estos valores antes de permitir el acceso a la subida o descarga de archivos.
La version almacenada en la base de datos cambia tras un restablecimiento de
contrasena; por ello, las sesiones que se hubieran creado con la version
anterior dejan de ser validas.

La entrega de codigo incluye rutas Flask que prestan la funcionalidad protegida.
No obstante, la interfaz actual devuelve HTML y no una API REST JSON completa.
Para satisfacer literalmente A.3.2, antes de la entrega final se deben anadir
endpoints REST equivalentes (por ejemplo, `/api/files` y `/api/files/<id>`) con
respuestas JSON, codigos HTTP y la misma autenticacion y autorizacion que se
describe en este apartado. No se debe afirmar que dichos endpoints ya existen
si no se implementan.

## A.3.1 Registro de usuarios e inicio de sesion con hash de contrasenas

### Modelo de datos y validacion

La tabla `users` almacena `username`, `email`, `password_hash`,
`session_version` y `role`. El nombre de usuario es la clave primaria, el email
es unico y ambos campos se validan en el servidor antes de insertar datos. El
nombre de usuario acepta de tres a treinta caracteres alfanumericos o guiones
bajos. El email se normaliza a minusculas y se comprueba con una expresion
regular basica. Las restricciones `PRIMARY KEY` y `UNIQUE` de la base de datos
constituyen una segunda barrera contra cuentas duplicadas.

La politica de contrasenas exige entre ocho y dieciseis caracteres y, como
minimo, una mayuscula, una minuscula y un digito. La comprobacion se realiza en
el servidor, no solo en el formulario HTML, de manera que una peticion creada
manualmente no pueda eludirla. Esta politica es una decision del prototipo
academico; en una version de produccion se permitirian contrasenas largas y
passphrases, respetando el limite de entrada de bcrypt [1].

### Almacenamiento seguro de contrasenas

Las contrasenas nunca se guardan en texto plano ni se cifran de manera
reversible. El controlador usa `bcrypt.gensalt()` y `bcrypt.hashpw()` para
generar un hash bcrypt con una sal aleatoria por contrasena. Solo la cadena del
hash se persiste en `users.password_hash`. Durante el inicio de sesion,
`bcrypt.checkpw()` compara la contrasena introducida con ese hash; no se
recupera ni se transmite la contrasena original. bcrypt es un algoritmo lento y
adaptativo destinado al almacenamiento de contrasenas, por lo que incrementa el
coste de intentos masivos si se expone la base de datos [1].

El registro sigue este flujo:

1. El controlador recibe `username`, `email` y `password` mediante HTTPS en un
   despliegue real.
2. Valida sintaxis, politica de contrasena y unicidad de username y email.
3. Genera el hash bcrypt con sal y guarda solo el hash usando una consulta
   parametrizada.
4. Redirige al formulario de inicio de sesion sin incluir secretos en la
   respuesta.

El inicio de sesion recibe el nombre de usuario y la contrasena, obtiene el hash
mediante una consulta parametrizada y llama a `verify_password`. Tanto para una
contrasena incorrecta como para un usuario inexistente devuelve el mensaje
generico `Invalid credentials.`. Esto reduce la enumeracion de cuentas. Si la
verificacion es correcta, se limpia la sesion previa y se crea una nueva sesion
autenticada.

Como medida adicional frente a fuerza bruta, el sistema registra intentos
fallidos por usuario en `login_attempts`. Cinco fallos consecutivos activan un
bloqueo de cinco minutos. Un inicio de sesion correcto elimina el contador. La
aplicacion tambien configura la cookie de sesion con `HttpOnly=True` y
`SameSite=Lax`; `HttpOnly` evita que JavaScript lea la cookie y `SameSite` ayuda
a limitar solicitudes cross-site no deseadas [4].

**Evidencia a incluir.** Se debe mostrar una captura pequena de un registro
correcto y de un intento fallido, y una consulta o fragmento que evidencie que
la columna contiene un hash bcrypt y no `Password123`. Tambien conviene incluir
la prueba de los cinco intentos fallidos seguida de un inicio de sesion correcto
rechazado durante el bloqueo.

## A.3.2 Desarrollo seguro de la API y control de acceso

### Autenticacion y gestion de sesiones

El mecanismo de autenticacion implementado es una sesion firmada de Flask, no
un JWT ni una API key. Es adecuado para la interfaz web servidor-renderizada del
prototipo: el navegador recibe una cookie de sesion y el decorador
`login_required` protege las rutas privadas. El decorador comprueba que
`logged_in` sea verdadero, que haya un `username` y que `session_version`
coincida con la version almacenada para ese usuario. Si alguna comprobacion
falla, borra la sesion y redirige al inicio de sesion.

La clave que firma la sesion no debe estar hardcodeada ni subirse a Git. La
version actual usa `os.urandom(24)`, que genera una clave nueva al reiniciar el
proceso. Esto es aceptable solo para demostraciones locales, pues invalida todas
las sesiones tras un reinicio. Para un despliegue real se debe suministrar una
clave aleatoria estable mediante una variable de entorno o un gestor de
secretos. Tambien se debe activar `SESSION_COOKIE_SECURE=True` y HTTPS en
produccion; Flask solo enviara cookies marcadas como Secure por HTTPS [4].

### Autorizacion por propiedad del recurso

La autenticacion responde a la pregunta «quien es el usuario»; la autorizacion
responde a «puede realizar esta accion sobre este recurso». En la descarga,
`find_owned_file(database, file_id, owner)` consulta el archivo con ambas
condiciones: identificador del archivo y propietario igual al usuario de la
sesion. Por tanto, conocer o modificar el `file_id` de otro usuario no basta
para descargarlo. La subida asocia el archivo nuevo al `session['username']`.

La tabla contiene una columna `role`, pero el codigo actual no usa todavia
roles de administrador. La autorizacion implementada es control de acceso por
propiedad. Si el caso de estudio requiere administradores, debe crearse un
decorador de rol y aplicar el principio de minimo privilegio; no es correcto
presentar la columna `role` como un RBAC ya implementado.

### Endpoints REST requeridos para completar el apartado

La funcionalidad actual debe exponerse ademas mediante una API REST. La tabla
siguiente define una propuesta coherente que se debe implementar antes de
describirla como resultado final.

| Endpoint | Metodo | Autenticacion/autorizacion | Resultado esperado |
| --- | --- | --- | --- |
| `/api/auth/register` | POST | Publico; valida entradas | `201 Created` o error de validacion `400` |
| `/api/auth/login` | POST | Publico; verifica bcrypt y aplica lockout | Sesion segura o token de corta vida; `401` si falla |
| `/api/files` | GET | Sesion valida; solo archivos propios | `200 OK` con metadatos del propietario |
| `/api/files` | POST | Sesion valida; valida archivo | `201 Created` con identificador del archivo |
| `/api/files/<file_id>` | GET | Sesion valida y propiedad del archivo | Descarga; `403` o `404` si no es propietario |

Las respuestas de error deben utilizar codigos HTTP coherentes, no incluir
trazas internas, nombres de tablas ni secretos. Toda entrada debe validarse en
el servidor y todas las consultas deben seguir siendo parametrizadas. Para una
API consumida por terceros, se debe decidir y justificar autenticacion mediante
Bearer token de vida corta, rotacion/revocacion, validacion de audiencia y
almacenamiento de secretos fuera del repositorio. Esa seria una ampliacion del
modelo de sesiones web actual, no una caracteristica ya implementada.

**Evidencia a incluir.** Para cada endpoint REST implementado, incluir una
captura parcial de Postman o `curl` con la solicitud, el codigo HTTP y una
respuesta saneada. Deben demostrarse al menos: acceso anonimo rechazado, sesion
o token invalido rechazado, usuario autenticado que lista sus archivos y un
usuario que intenta descargar un archivo de otra cuenta.

## A.3.3 Mecanismo seguro de restablecimiento de contrasena

El flujo de recuperacion comienza en `/forgot-password`. El usuario proporciona
un email y la aplicacion responde siempre con el mismo mensaje: «If the email
exists, a password reset link has been created». Asi no revela si la direccion
esta registrada. Para un email valido y existente, el sistema limita las
solicitudes a dos por hora y crea un token de recuperacion.

El token se genera con `secrets.token_urlsafe(32)`, un generador
criptograficamente seguro. El valor que viaja una unica vez en el enlace no se
guarda directamente: se calcula su SHA-256 y se almacena solo el hash en
`password_reset_tokens`, junto con el usuario, fecha de expiracion y fecha de
uso. El token expira tras quince minutos. Al solicitar uno nuevo se invalidan
los tokens no usados anteriores del mismo usuario. Estas decisiones siguen las
propiedades recomendadas de un token de recuperacion: aleatorio, suficientemente
largo, vinculado a una cuenta, de un solo uso y con caducidad [2].

Al abrir `/reset-password/<token>`, la aplicacion calcula el hash del token y
comprueba que exista, no haya caducado y no se haya consumido. El formulario
solicita la nueva contrasena dos veces y aplica la misma politica del registro.
`reset_password_with_token` abre una transaccion SQLite inmediata: verifica el
token, actualiza el hash bcrypt, incrementa `session_version` y marca el token
como usado en una unica operacion. La transaccion impide que dos solicitudes
paralelas reutilicen el mismo token. Finalmente se borra la sesion y el usuario
debe autenticarse de nuevo con la contrasena nueva.

En desarrollo, el enlace se imprime en la terminal. En produccion debe enviarse
mediante un canal externo confiable, por ejemplo email sobre HTTPS; nunca se
debe registrar el token en logs. Tambien debe enviarse una notificacion tras el
cambio de contrasena y configurarse una politica `Referrer-Policy: no-referrer`
en la pagina de restablecimiento para reducir filtraciones del token por la URL
[2].

**Evidencia a incluir.** Mostrar de forma parcial un token valido, su registro
hash en la base de datos, un restablecimiento correcto y los resultados de
token caducado, manipulado y reutilizado. El valor completo del token no debe
aparecer en el informe ni en una captura publica.

## A.3.4 Subida y descarga segura de archivos

La ruta de subida y la ruta `/download/<int:file_id>` estan protegidas por
`login_required`. La subida acepta un maximo de 1 MB y permite unicamente las
extensiones TXT, PDF y PNG. El nombre enviado por el navegador se sanea con
`secure_filename`; el servidor conserva ese nombre saneado como metadato, pero
genera el nombre real de almacenamiento concatenando un UUID aleatorio. De este
modo, dos usuarios pueden subir `documento.pdf` sin sobrescribirse y el nombre
en disco no es predecible. La descarga se realiza siempre a traves de un
endpoint que verifica propiedad antes de llamar a `send_from_directory`; los
archivos no se exponen mediante una URL publica directa.

La tabla `files` mantiene los metadatos necesarios: identificador, nombre
original saneado, nombre interno unico, propietario y fecha de subida. La clave
foranea a `users` preserva la relacion con el propietario. Para evitar path
traversal, la aplicacion no forma una ruta a partir de la entrada del usuario:
recupera el `stored_name` autorizado desde la base de datos y lo entrega a
`send_from_directory`.

La validacion actual por extension, el saneamiento del nombre, el limite de
tamano, el UUID y el control de acceso son defensas utiles. Sin embargo, la
extension y la cabecera `Content-Type` pueden falsificarse. Antes de la entrega
final se debe validar el tipo real del contenido mediante una libreria de
identificacion MIME, rechazar archivos corruptos o con firmas incompatibles y,
si el entorno lo permite, analizarlos con antivirus. Tambien es recomendable
guardar los archivos fuera del directorio servido por la aplicacion o en un
almacenamiento separado con permisos restringidos. Estas medidas corresponden a
las recomendaciones de OWASP para carga de archivos [3].

**Evidencia a incluir.** Incluir capturas pequenas de: subida valida, rechazo
por extension, rechazo por superar 1 MB, dos usuarios subiendo un archivo con
el mismo nombre y un intento de descargar el archivo de otra persona. La
evidencia debe mostrar que los nombres internos son distintos y que el acceso
cruzado no entrega el contenido.

## Limitaciones y trabajo pendiente antes de presentar una version final

La aplicacion ya demuestra hashing bcrypt, validacion de servidor, bloqueo
temporal de inicio de sesion, sesiones protegidas, recuperacion con token de
un solo uso y autorizacion por propiedad de archivos. No obstante, los puntos
siguientes deben completarse o declararse expresamente como limitaciones:

1. Implementar los endpoints REST JSON propuestos y sus pruebas, ya que las
   rutas actuales son principalmente formularios HTML.
2. Mover `SECRET_KEY` a una variable de entorno o gestor de secretos y activar
   HTTPS y cookie Secure fuera de desarrollo.
3. Implementar verificacion real MIME/firma de archivo y, si es posible,
   antimalware; la lista de extensiones por si sola no es suficiente.
4. Anadir proteccion CSRF para formularios que cambian estado y cabeceras de
   seguridad apropiadas.
5. Ejecutar y documentar las pruebas automatizadas en el entorno final. El
   archivo `tests/test_auth.py` contiene pruebas de hash bcrypt, validaciones,
   bloqueo, rutas protegidas, configuracion de cookie y colisiones de nombre;
   debe adjuntarse una captura pequena del resumen de `pytest`.

## Referencias

1. OWASP Foundation. *Password Storage Cheat Sheet*. Disponible en:
   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
   (consultado el 14 de septiembre de 2026).
2. OWASP Foundation. *Forgot Password Cheat Sheet*. Disponible en:
   https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
   (consultado el 14 de septiembre de 2026).
3. OWASP Foundation. *File Upload Cheat Sheet*. Disponible en:
   https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
   (consultado el 14 de septiembre de 2026).
4. Pallets Projects. *Configuration Handling - Flask Documentation*. Disponible
   en: https://flask.palletsprojects.com/en/stable/config/ (consultado el 14 de
   septiembre de 2026).
