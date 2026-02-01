---

<img src="https://github.com/somospye/.github/blob/e0ab2bf61b679d7746e5c1114baa5f37c354d778/assets/pyebanner.png" />

Somos la comunidad hispana más grande de **programación** y **estudio** en Discord. [¡Siéntase bienvenido/a!](https://discord.gg/programacion) 😄

---

<div align="center">
  <img src="assets/logo.png" alt="Sentinel Logo" width="200" />
  <h1>Sentinel</h1>
  <p>Bot de seguridad de nuestra comunidad.</p>

  [![Discord](https://img.shields.io/discord/768278151435386900?color=5865F2&label=Discord&logo=discord&logoColor=white)](https://discord.gg/programacion)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

---

**Sentinel** es el Guardián de [Programadores y Estudiantes](https://discord.gg/programacion). Diseñado para ser escalable, rápido y eficiente, este bot se encarga de automatizar la moderación y mejorar la seguridad de nuestro servidor.

## Características Principales

- **Logs Detallados:** Seguimiento exhaustivo de eventos en el servidor (roles, canales, etc.).
- **Análisis de Imágenes:** Detección de scams mediante comparación de imágenes utilizando modelos de Inteligencia Artificial.

## Instalación y Uso

### Requisitos Previos
- [Go](https://go.dev/dl/) (versión 1.25.6 o superior)
- [Git](https://git-scm.com/)

### Configuración
1. Clona el repositorio:
   ```bash
   git clone https://github.com/somospye/sentinel.git
   cd sentinel
   ```
2. Configura las variables de entorno:
   ```bash
   cp .env.example .env
   # Edita el archivo .env con tu BOT_TOKEN
   ```
3. Instala dependencias:
   ```bash
   go mod tidy
   ```
4. Ejecuta el proyecto:
   ```bash
   go run main.go
   ```

## Contribuir

¡Las contribuciones son bienvenidas! Si quieres ayudar a mejorar Sentinel, revisa nuestra [Guía de Contribución](./contributing.md).

## Licencia

Este proyecto está bajo la [Licencia MIT](./LICENSE).

