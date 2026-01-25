# Guía de Contribución

¡Bienvenido a la guía de contribución de **Sentinel**!
Antes de comenzar, asegúrate de leer y seguir todas las instrucciones de este documento para que tu colaboración pueda integrarse sin problemas.

---

## 🚀 Preparar el entorno

1. **Haz un fork** de este repositorio desde el botón `Fork` en la parte superior.

2. **Clona tu fork en local**:
   ```bash
   git clone https://github.com/TU_USUARIO/sentinel
   cd sentinel
   ```

3. **Instala Go**: Asegúrate de tener Go 1.21 o superior instalado. Puedes descargarlo en [go.dev](https://go.dev/).

4. **Instala dependencias**:
   ```bash
   go mod tidy
   ```

5. **Configura [Lefthook](https://github.com/evilmartians/lefthook)**:
   Es obligatorio para asegurar la consistencia del código:
   ```bash
   lefthook install
   ```
   Esto asegura que se apliquen automáticamente las verificaciones de formato (`go fmt`) y mensajes de commit antes de cada *commit*.

---

## 📝 Convenciones de Commits

* Utilizamos el estándar [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
* **No uses emojis** en los mensajes de commit.
* Lefthook validará esto automáticamente.
* El estándar es: `<tipo>(alcance opcional): descripción`
* Ejemplo: `feat(moderation): add warn system`

---

## 🔑 Variables de Entorno

Configura el archivo `.env` con las siguientes variables:

```env
BOT_TOKEN=DISCORD_TOKEN
```

---

## 🤖 Ejecución

Para ejecutar el bot en modo desarrollo:

```bash
go run main.go
```

Para compilar un binario:

```bash
go build -o sentinel .
```

---

## 🔀 Pull Requests

1. Trabaja siempre en una rama nueva creada desde `main`.
   ```bash
   git checkout -b feat/nombre-de-tu-feature
   ```

2. Asegúrate de formatear el código antes de enviar (o deja que Lefthook lo haga):
   ```bash
   go fmt ./...
   ```

3. Escribe una descripción clara de los cambios en la PR. Explica el "qué" y el "por qué".

4. Nombra la PR de forma coherente con el commit principal (siguiendo **Conventional Commits**).

5. Espera la revisión. Se pedirá que ajustes el código si no cumple con las reglas o estilos definidos.
