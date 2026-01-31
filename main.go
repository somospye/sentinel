package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sentinel/internal/automod"

	"github.com/bwmarrin/discordgo"
	"github.com/joho/godotenv"

	ort "github.com/yalue/onnxruntime_go"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Printf("Advertencia: Error cargando archivo .env (%s)", err)
	}

	fmt.Println("Cargando ONNX Runtime desde:", automod.GetSharedLibPath())
	ort.SetSharedLibraryPath(automod.GetSharedLibPath())

	e := ort.InitializeEnvironment()
	if e != nil {
		_ = fmt.Errorf("Error inicializando ONNX Runtime: %w", e)
	}

	token := os.Getenv("BOT_TOKEN")
	if token == "" {
		log.Fatal("BOT_TOKEN no está configurado")
	}

	ownerID := os.Getenv("OWNER_ID")

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatalf("Error creando sesión de Discord: %v", err)
	}

	manager := automod.NewManager("./config.json")
	scamPath := "./assets/scam"
	err = manager.Scanner.LoadScamImages(scamPath)
	if err != nil {
		log.Printf("Advertencia: Error cargando imágenes de scam (%v)", err)
	}

	dg.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		manager.AnalyzeMessage(s, m)
	})

	dg.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if i.Type != discordgo.InteractionApplicationCommand {
			return
		}

		data := i.ApplicationCommandData()
		switch data.Name {
		case "set":
			if i.Member.User.ID != ownerID {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "No tienes permiso para usar este comando.",
						Flags:   discordgo.MessageFlagsEphemeral,
					},
				})
				return
			}
			for _, opt := range data.Options {
				switch opt.Name {
				case "logs-sanctions":
					channel := opt.ChannelValue(s)
					manager.SetLogChannel(i.GuildID, channel.ID)
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: fmt.Sprintf("Canal de logs de sanciones configurado a <#%s>", channel.ID),
							Flags:   discordgo.MessageFlagsEphemeral,
						},
					})
				case "logs-events":
					channel := opt.ChannelValue(s)
					manager.SetEventsChannel(i.GuildID, channel.ID)
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: fmt.Sprintf("Canal de logs de eventos configurado a <#%s>", channel.ID),
							Flags:   discordgo.MessageFlagsEphemeral,
						},
					})
				case "nsfw-detection":
					enabled := opt.BoolValue()
					manager.SetNSFWDetection(i.GuildID, enabled)
					status := "desactivada"
					if enabled {
						status = "activada"
					}
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: fmt.Sprintf("Detección de NSFW %s correctamente.", status),
							Flags:   discordgo.MessageFlagsEphemeral,
						},
					})
				}
			}

		case "add-scam":
			if i.Member.Permissions&discordgo.PermissionBanMembers == 0 {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Necesitas permiso de baneo para agregar imágenes de scam.",
						Flags:   discordgo.MessageFlagsEphemeral,
					},
				})
				return
			}
			attachmentID := data.Options[0].Value.(string)
			attachment := data.Resolved.Attachments[attachmentID]
			if !strings.HasPrefix(attachment.ContentType, "image/") {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "El archivo debe ser una imagen.",
						Flags:   discordgo.MessageFlagsEphemeral,
					},
				})
				return
			}

			resp, err := http.Get(attachment.URL)
			if err != nil {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Error descargando la imagen.",
						Flags:   discordgo.MessageFlagsEphemeral,
					},
				})
				return
			}
			defer resp.Body.Close()

			fileName := fmt.Sprintf("scam_%d%s", time.Now().Unix(), filepath.Ext(attachment.Filename))
			out, err := os.Create(filepath.Join(scamPath, fileName))
			if err != nil {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Error guardando el archivo.",
						Flags:   discordgo.MessageFlagsEphemeral,
					},
				})
				return
			}
			defer out.Close()
			io.Copy(out, resp.Body)

			manager.Scanner.LoadScamImages(scamPath)

			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Imagen agregada a la lista de scams como `%s`.", fileName),
					Flags:   discordgo.MessageFlagsEphemeral,
				},
			})
		}
	})

	dg.AddHandler(func(s *discordgo.Session, r *discordgo.GuildRoleCreate) {
		manager.LogEventWithAudit(s, r.GuildID, discordgo.AuditLogActionRoleCreate, &discordgo.MessageEmbed{
			Title:       "🆕 Rol Creado",
			Description: fmt.Sprintf("Nombre: %s\nID: %s", r.Role.Name, r.Role.ID),
			Color:       0x2ecc71,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	})

	dg.AddHandler(func(s *discordgo.Session, r *discordgo.GuildRoleDelete) {
		manager.LogEventWithAudit(s, r.GuildID, discordgo.AuditLogActionRoleDelete, &discordgo.MessageEmbed{
			Title:       "🗑️ Rol Eliminado",
			Description: fmt.Sprintf("ID: %s", r.RoleID),
			Color:       0xe74c3c,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	})

	dg.AddHandler(func(s *discordgo.Session, r *discordgo.GuildRoleUpdate) {
		auditLog, err := s.GuildAuditLog(r.GuildID, "", "", int(discordgo.AuditLogActionRoleUpdate), 1)
		changeDetail := fmt.Sprintf("Nombre: %s\nID: %s", r.Role.Name, r.Role.ID)
		executor := "Desconocido"

		if err == nil && len(auditLog.AuditLogEntries) > 0 {
			entry := auditLog.AuditLogEntries[0]
			executor = fmt.Sprintf("<@%s>", entry.UserID)

			var changes []string
			for _, change := range entry.Changes {
				key := string(*change.Key)
				switch key {
				case "name":
					changes = append(changes, fmt.Sprintf("📝 **Nombre:** `%v` ➔ `%v`", change.OldValue, change.NewValue))
				case "color":
					changes = append(changes, fmt.Sprintf("🎨 **Color:** `#%06X` ➔ `#%06X`", forceInt64(change.OldValue), forceInt64(change.NewValue)))
				case "permissions":
					oldPerm := forceInt64(change.OldValue)
					newPerm := forceInt64(change.NewValue)
					added, removed := diffPermissions(oldPerm, newPerm)
					if len(added) > 0 {
						changes = append(changes, "✅ **Permisos añadidos:** "+strings.Join(added, ", "))
					}
					if len(removed) > 0 {
						changes = append(changes, "❌ **Permisos quitados:** "+strings.Join(removed, ", "))
					}
				case "hoist":
					status := "No"
					if change.NewValue.(bool) {
						status = "Si"
					}
					changes = append(changes, fmt.Sprintf("📁 **Mostrar por separado:** `%v`", status))
				case "mentionable":
					status := "No"
					if change.NewValue.(bool) {
						status = "Si"
					}
					changes = append(changes, fmt.Sprintf("📢 **Mencionable:** `%v`", status))
				default:
					fmt.Printf("DEBUG: Role change key ignored: %s\n", key)
				}
			}
			if len(changes) > 0 {
				changeDetail = strings.Join(changes, "\n") + "\n" + fmt.Sprintf("ID: %s", r.Role.ID)
			}
		}

		manager.LogEvent(s, r.GuildID, &discordgo.MessageEmbed{
			Title:       "✏️ Rol Actualizado",
			Description: fmt.Sprintf("Responsable: %s\n%s", executor, changeDetail),
			Color:       0xf1c40f,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	})

	dg.AddHandler(func(s *discordgo.Session, c *discordgo.ChannelCreate) {
		manager.LogEventWithAudit(s, c.GuildID, discordgo.AuditLogActionChannelCreate, &discordgo.MessageEmbed{
			Title:       "🆕 Canal Creado",
			Description: fmt.Sprintf("Nombre: <#%s>\nTipo: %v", c.ID, c.Type),
			Color:       0x3498db,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	})

	dg.AddHandler(func(s *discordgo.Session, c *discordgo.ChannelDelete) {
		manager.LogEventWithAudit(s, c.GuildID, discordgo.AuditLogActionChannelDelete, &discordgo.MessageEmbed{
			Title:       "🗑️ Canal Eliminado",
			Description: fmt.Sprintf("Nombre: %s\nID: %s", c.Name, c.ID),
			Color:       0xe67e22,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	})

	dg.AddHandler(func(s *discordgo.Session, c *discordgo.ChannelUpdate) {
		auditLog, err := s.GuildAuditLog(c.GuildID, "", "", int(discordgo.AuditLogActionChannelUpdate), 1)
		changeDetail := fmt.Sprintf("Nombre: <#%s>\nID: %s\nTipo: %v", c.ID, c.ID, c.Type)
		executor := "Desconocido"

		if err == nil && len(auditLog.AuditLogEntries) > 0 {
			entry := auditLog.AuditLogEntries[0]
			executor = fmt.Sprintf("<@%s>", entry.UserID)

			var changes []string
			for _, change := range entry.Changes {
				key := string(*change.Key)
				switch key {
				case "name":
					changes = append(changes, fmt.Sprintf("📝 **Nombre:** `%v` ➔ `%v`", change.OldValue, change.NewValue))
				case "topic":
					changes = append(changes, "📌 **Tema/Topic:** Ha sido modificado.")
				case "parent_id":
					changes = append(changes, "📂 **Categoría:** El canal ha sido movido.")
				case "bitrate":
					oldB := forceInt64(change.OldValue) / 1000
					newB := forceInt64(change.NewValue) / 1000
					changes = append(changes, fmt.Sprintf("🔊 **Bitrate:** `%dkbps` ➔ `%dkbps`", oldB, newB))
				}
			}
			if len(changes) > 0 {
				changeDetail = strings.Join(changes, "\n") + "\n" + fmt.Sprintf("ID: %s", c.ID)
			}
		}

		manager.LogEvent(s, c.GuildID, &discordgo.MessageEmbed{
			Title:       "✏️ Canal/Categoría Actualizado",
			Description: fmt.Sprintf("Responsable: %s\n%s", executor, changeDetail),
			Color:       0xf39c12,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
	})

	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent | discordgo.IntentsGuilds | discordgo.IntentsGuildMembers

	err = dg.Open()
	if err != nil {
		log.Fatalf("Error abriendo la conexión: %v", err)
	}

	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "set",
			Description: "Configura canales de logs",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionChannel,
					Name:        "logs-sanctions",
					Description: "Canal para sanciones de automod",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionChannel,
					Name:        "logs-events",
					Description: "Canal para eventos del servidor (roles, canales, etc)",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "nsfw-detection",
					Description: "Habilitar/Deshabilitar la detección de contenido NSFW",
					Required:    false,
				},
			},
		},
		{
			Name:        "add-scam",
			Description: "Agrega una imagen a la lista de comparación de phash",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionAttachment,
					Name:        "imagen",
					Description: "La imagen sospechosa",
					Required:    true,
				},
			},
		},
	}

	fmt.Println("Comandos registrados...")
	for _, cmd := range commands {
		_, err := dg.ApplicationCommandCreate(dg.State.User.ID, "", cmd)
		if err != nil {
			log.Printf("No se pudo crear el comando '%v': %v", cmd.Name, err)
		} else {
			log.Printf("Comando '%v' registrado correctamente", cmd.Name)
		}
	}

	go func() {
		statuses := []string{"Vigilando %d usuarios", "Te veo", "Sentinel te vigila"}
		i := 0
		for {
			totalMembers := 0
			for _, g := range dg.State.Guilds {
				totalMembers += g.MemberCount
			}

			status := statuses[i%len(statuses)]
			if strings.Contains(status, "%d") {
				status = fmt.Sprintf(status, totalMembers)
			}

			dg.UpdateGameStatus(0, status)
			i++
			time.Sleep(30 * time.Second)
		}
	}()

	fmt.Println("El bot esta corriendo, presiona CTRL-C para salir.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	dg.Close()
	defer ort.DestroyEnvironment()
}

func diffPermissions(oldPerm, newPerm int64) (added, removed []string) {
	permNames := map[int64]string{
		discordgo.PermissionAdministrator:      "Administrador",
		discordgo.PermissionManageGuild:        "Gestionar Servidor",
		discordgo.PermissionManageRoles:        "Gestionar Roles",
		discordgo.PermissionManageChannels:     "Gestionar Canales",
		discordgo.PermissionKickMembers:        "Expulsar Miembros",
		discordgo.PermissionBanMembers:         "Banear Miembros",
		discordgo.PermissionManageMessages:     "Gestionar Mensajes",
		discordgo.PermissionMentionEveryone:    "Mencionar Everyone",
		discordgo.PermissionManageWebhooks:     "Gestionar Webhooks",
		discordgo.PermissionManageNicknames:    "Gestionar Apodos",
		discordgo.PermissionViewAuditLogs:      "Ver Registro de Auditoría",
		discordgo.PermissionSendMessages:       "Enviar Mensajes",
		discordgo.PermissionEmbedLinks:         "Insertar Enlaces",
		discordgo.PermissionAttachFiles:        "Adjuntar Archivos",
		discordgo.PermissionReadMessageHistory: "Leer Historial de Mensajes",
		discordgo.PermissionAddReactions:       "Añadir Reacciones",
		discordgo.PermissionVoiceConnect:       "Conectar (Voz)",
		discordgo.PermissionVoiceSpeak:         "Hablar (Voz)",
		discordgo.PermissionVoiceMuteMembers:   "Silenciar Miembros (Voz)",
		discordgo.PermissionVoiceDeafenMembers: "Ensordecer Miembros (Voz)",
		discordgo.PermissionVoiceMoveMembers:   "Mover Miembros (Voz)",
		discordgo.PermissionVoiceUseVAD:        "Usar Actividad de Voz",
		0x00000100:                             "Prioridad de Palabra",
		0x00000200:                             "Video/Stream",
		discordgo.PermissionChangeNickname:     "Cambiar Apodo",
	}

	for bit, name := range permNames {
		if oldPerm&bit == 0 && newPerm&bit != 0 {
			added = append(added, name)
		}
		if oldPerm&bit != 0 && newPerm&bit == 0 {
			removed = append(removed, name)
		}
	}
	return
}

func forceInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	case string:
		var n int64
		_, err := fmt.Sscanf(val, "%v", &n)
		if err != nil {
			// Fallback para otros formatos
			fmt.Printf("Error convirtiendo string '%s' a int64: %v\n", val, err)
		}
		return n
	default:
		return 0
	}
}
