package automod

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/dlclark/regexp2"
)

type Config struct {
	LogChannelID    string `json:"log_channel_id"`
	EventsChannelID string `json:"events_channel_id"`
	NSFWDetection   bool   `json:"nsfw_detection"`
}

type Manager struct {
	Scanner        *PhashScanner
	ScamFilters    []*regexp2.Regexp
	SpamFilters    []IFilter
	GuildConfig    map[string]*Config
	mu             sync.RWMutex
	mentionHistory map[string][]time.Time
	messageHistory map[string][]time.Time
	configPath     string
	activityPath   string
	LastActivity   map[string]time.Time
}

func NewManager(configPath string) *Manager {
	m := &Manager{
		Scanner:        NewPhashScanner(),
		ScamFilters:    GetScamFilterList(),
		SpamFilters:    SpamFilterList,
		GuildConfig:    make(map[string]*Config),
		mentionHistory: make(map[string][]time.Time),
		messageHistory: make(map[string][]time.Time),
		LastActivity:   make(map[string]time.Time),
		configPath:     configPath,
		activityPath:   strings.TrimSuffix(configPath, ".json") + "_activity.json",
	}
	m.LoadConfig()
	m.LoadActivity()
	return m
}

func (m *Manager) SetLogChannel(guildID, channelID string) {
	m.mu.Lock()
	if _, ok := m.GuildConfig[guildID]; !ok {
		m.GuildConfig[guildID] = &Config{}
	}
	m.GuildConfig[guildID].LogChannelID = channelID
	m.mu.Unlock()
	m.SaveConfig()
}

func (m *Manager) GetLogChannel(guildID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cfg, ok := m.GuildConfig[guildID]; ok {
		return cfg.LogChannelID
	}
	return ""
}

func (m *Manager) SetEventsChannel(guildID, channelID string) {
	m.mu.Lock()
	if _, ok := m.GuildConfig[guildID]; !ok {
		m.GuildConfig[guildID] = &Config{}
	}
	m.GuildConfig[guildID].EventsChannelID = channelID
	m.mu.Unlock()
	m.SaveConfig()
}

func (m *Manager) GetEventsChannel(guildID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cfg, ok := m.GuildConfig[guildID]; ok {
		return cfg.EventsChannelID
	}
	return ""
}

func (m *Manager) SetNSFWDetection(guildID string, enabled bool) {
	m.mu.Lock()
	if _, ok := m.GuildConfig[guildID]; !ok {
		m.GuildConfig[guildID] = &Config{}
	}
	m.GuildConfig[guildID].NSFWDetection = enabled
	m.mu.Unlock()
	m.SaveConfig()
}

func (m *Manager) IsNSFWEnabled(guildID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cfg, ok := m.GuildConfig[guildID]; ok {
		return cfg.NSFWDetection
	}
	return false
}

func (m *Manager) AnalyzeMessage(s *discordgo.Session, msg *discordgo.MessageCreate) {
	if msg.Author.Bot {
		return
	}

	content := msg.Content
	for _, filter := range m.SpamFilters {
		match, _ := filter.Filter.FindStringMatch(content)
		if match != nil {
			detail := fmt.Sprintf("Match: `%s`\nRegex: `%s`", match.String(), filter.Filter.String())
			if filter.WarnMessage != "" {
				detail = filter.WarnMessage + "\n" + detail
			}
			m.TakeAction(s, msg, "Spam Filter", detail, filter.Mute, nil)
			return
		}
	}

	for _, filter := range m.ScamFilters {
		match, _ := filter.FindStringMatch(content)
		if match != nil {
			detail := fmt.Sprintf("Posible estafa detectada en el texto.\nMatch: `%s`\nRegex: `%s`", match.String(), filter.String())
			m.TakeAction(s, msg, "Scam Phrase Filter", detail, false, nil)
			return
		}
	}

	if len(msg.Mentions) > 5 {
		m.TakeAction(s, msg, "Mass Mention", "Demasiadas menciones en un solo mensaje.", true, nil)
		return
	}

	if m.isSpamming(msg.Author.ID) {
		m.TakeAction(s, msg, "Spam", "Enviando mensajes demasiado rápido.", false, nil)
		return
	}

	// Lógica de usuario nuevo o inactivo (no habla hace > 1 semana)
	isNewOrInactive := false
	m.mu.RLock()
	lastSeen, ok := m.LastActivity[msg.Author.ID]
	m.mu.RUnlock()

	if !ok {
		isNewOrInactive = true
	} else if time.Since(lastSeen) > 7*24*time.Hour {
		isNewOrInactive = true
	}

	// También checamos JoinedAt si está disponible
	if !isNewOrInactive && msg.Member != nil {
		joinedAt := msg.Member.JoinedAt
		if time.Since(joinedAt) < 7*24*time.Hour {
			isNewOrInactive = true
		}
	}

	// Solo analiza imágenes si hay 2 o más, a menos que sea un usuario nuevo/inactivo
	imgCount := 0
	for _, att := range msg.Attachments {
		if strings.HasPrefix(att.ContentType, "image/") {
			imgCount++
		}
	}

	shouldAnalyze := (isNewOrInactive && imgCount >= 1) || imgCount >= 2

	if shouldAnalyze {
		for _, att := range msg.Attachments {
			if strings.HasPrefix(att.ContentType, "image/") {
				go func(attachment *discordgo.MessageAttachment) {
					// 1. Phash (Scam)
					img, err := DownloadImage(attachment.URL)
					if err == nil {
						res := m.Scanner.Compare(img)
						if res.Match {
							detail := fmt.Sprintf("Imagen detectada: %s\nDistancias: [P:%d D:%d A:%d] Avg: **%d**",
								res.Name, res.PDist, res.DDist, res.ADist, res.AvgDist)
							m.TakeAction(s, msg, "Imagen Scam", detail, true, res.CropJPEG)
							return
						}
					}

					// 2. NSFW check
					if m.IsNSFWEnabled(msg.GuildID) {
						isNSFW, err := CheckNSFW(attachment.URL)
						if err == nil && isNSFW {
							var crop []byte
							if img != nil {
								var buf bytes.Buffer
								jpeg.Encode(&buf, img, &jpeg.Options{Quality: 60})
								crop = buf.Bytes()
							}
							m.TakeAction(s, msg, "Contenido NSFW", "Imagen detectada como no segura para el servidor.", true, crop)
						}
					}
				}(att)
			}
		}
	}

	m.mu.Lock()
	m.LastActivity[msg.Author.ID] = time.Now()
	m.mu.Unlock()
	m.SaveActivity()
}

func (m *Manager) TakeAction(s *discordgo.Session, msg *discordgo.MessageCreate, reason, detail string, mute bool, cropData []byte) {
	s.ChannelMessageDelete(msg.ChannelID, msg.ID)

	if mute {
		until := time.Now().Add(7 * 24 * time.Hour)
		if err := s.GuildMemberTimeout(msg.GuildID, msg.Author.ID, &until); err != nil {
			fmt.Printf("Error muteando usuario %s: %v\n", msg.Author.ID, err)
		}
	}

	logChannel := m.GetLogChannel(msg.GuildID)
	if logChannel != "" {
		embed := &discordgo.MessageEmbed{
			Title:       "🚨 Automod",
			Description: fmt.Sprintf("Usuario: <@%s> (%s)\nRazón: **%s**\nDetalle: %s", msg.Author.ID, msg.Author.String(), reason, detail),
			Color:       0xff0000,
			Timestamp:   time.Now().Format(time.RFC3339),
			Footer: &discordgo.MessageEmbedFooter{
				Text: "Sentinel Automod",
			},
		}

		messageData := &discordgo.MessageSend{
			Embeds: []*discordgo.MessageEmbed{embed},
		}

		if len(cropData) > 0 {
			embed.Image = &discordgo.MessageEmbedImage{
				URL: "attachment://evidence.jpg",
			}
			messageData.Files = []*discordgo.File{
				{
					Name:        "evidence.jpg",
					ContentType: "image/jpeg",
					Reader:      bytes.NewReader(cropData),
				},
			}
		}

		s.ChannelMessageSendComplex(logChannel, messageData)
	}
}

func (m *Manager) isSpamming(userID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	history := m.messageHistory[userID]

	var newHistory []time.Time
	for _, t := range history {
		if now.Sub(t) < 5*time.Second {
			newHistory = append(newHistory, t)
		}
	}

	newHistory = append(newHistory, now)
	m.messageHistory[userID] = newHistory

	return len(newHistory) > 5
}

func (m *Manager) LogEvent(s *discordgo.Session, guildID string, embed *discordgo.MessageEmbed) {
	channelID := m.GetEventsChannel(guildID)
	if channelID != "" {
		s.ChannelMessageSendEmbed(channelID, embed)
	}
}

func (m *Manager) GetLatestAuditLogExecutor(s *discordgo.Session, guildID string, actionType discordgo.AuditLogAction) string {
	auditLog, err := s.GuildAuditLog(guildID, "", "", int(actionType), 1)
	if err != nil || len(auditLog.AuditLogEntries) == 0 {
		return "Desconocido"
	}

	entry := auditLog.AuditLogEntries[0]
	return fmt.Sprintf("<@%s>", entry.UserID)
}

func (m *Manager) LogEventWithAudit(s *discordgo.Session, guildID string, actionType discordgo.AuditLogAction, embed *discordgo.MessageEmbed) {
	executor := m.GetLatestAuditLogExecutor(s, guildID, actionType)
	embed.Description = fmt.Sprintf("Responsable: %s\n%s", executor, embed.Description)
	m.LogEvent(s, guildID, embed)
}

func (m *Manager) SaveConfig() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.GuildConfig, "", "  ")
	if err != nil {
		fmt.Printf("Error serializando configuración: %v\n", err)
		return
	}

	err = os.WriteFile(m.configPath, data, 0644)
	if err != nil {
		fmt.Printf("Error guardando configuración en %s: %v\n", m.configPath, err)
	}
}

func (m *Manager) LoadConfig() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Error leyendo configuración en %s: %v\n", m.configPath, err)
		}
		return
	}

	err = json.Unmarshal(data, &m.GuildConfig)
	if err != nil {
		fmt.Printf("Error deserializando configuración: %v\n", err)
	}
}

func (m *Manager) SaveActivity() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.LastActivity, "", "  ")
	if err != nil {
		fmt.Printf("Error serializando actividad: %v\n", err)
		return
	}

	err = os.WriteFile(m.activityPath, data, 0644)
	if err != nil {
		fmt.Printf("Error guardando actividad en %s: %v\n", m.activityPath, err)
	}
}

func (m *Manager) LoadActivity() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.activityPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Error leyendo actividad en %s: %v\n", m.activityPath, err)
		}
		return
	}

	err = json.Unmarshal(data, &m.LastActivity)
	if err != nil {
		fmt.Printf("Error deserializando actividad: %v\n", err)
	}
}
