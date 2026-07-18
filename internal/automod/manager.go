package automod

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/dlclark/regexp2"
)

const ScamImageReason = "Imagen Scam"

type BotSession interface {
	GuildMemberDelete(guildID, userID string, options ...discordgo.RequestOption) error
	GuildChannels(guildID string, options ...discordgo.RequestOption) ([]*discordgo.Channel, error)
	ChannelMessages(channelID string, limit int, beforeID, afterID, aroundID string, options ...discordgo.RequestOption) ([]*discordgo.Message, error)
	ChannelMessageDelete(channelID, messageID string, options ...discordgo.RequestOption) error
	ChannelMessagesBulkDelete(channelID string, messages []string, options ...discordgo.RequestOption) error
	ChannelMessageSendComplex(channelID string, data *discordgo.MessageSend, options ...discordgo.RequestOption) (*discordgo.Message, error)
	GuildMemberTimeout(guildID, userID string, until *time.Time, options ...discordgo.RequestOption) error
}

type Config struct {
	LogChannelID    string `json:"log_channel_id"`
	EventsChannelID string `json:"events_channel_id"`
	NSFWDetection   bool   `json:"nsfw_detection"`
}

type Manager struct {
	Scanner        ImageScanner
	ScamFilters    []*regexp2.Regexp
	SpamFilters    []IFilter
	GuildConfig    map[string]*Config
	mu             sync.RWMutex
	mentionHistory map[string][]time.Time
	messageHistory map[string][]messageEntry
	configPath     string
	activityPath   string
	LastActivity   map[string]time.Time
}

type messageEntry struct {
	Content   string
	Timestamp time.Time
}

func NewManager(configPath string) *Manager {
	m := &Manager{
		Scanner:        CLIPScan(),
		ScamFilters:    GetScamFilterList(),
		SpamFilters:    SpamFilterList,
		GuildConfig:    make(map[string]*Config),
		mentionHistory: make(map[string][]time.Time),
		messageHistory: make(map[string][]messageEntry),
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

func (m *Manager) AnalyzeMessageEdit(s BotSession, msg *discordgo.MessageUpdate) {
	if msg.Author.Bot {
		return
	}

	if msg.Member != nil && slices.Contains(msg.Member.Roles, os.Getenv("ADMIN_ID")) {
		return
	}

	content := msg.Content
	if content == "" {
		return
	}

	for _, filter := range m.SpamFilters {
		match, _ := filter.Filter.FindStringMatch(content)
		if match != nil {
			detail := fmt.Sprintf("Match: `%s`\nRegex: `%s`\n[Mensaje editado]", match.String(), filter.Filter.String())
			if filter.WarnMessage != "" {
				detail = filter.WarnMessage + "\n" + detail
			}
			muteDur := time.Duration(0)
			if filter.Mute {
				muteDur = 7 * 24 * time.Hour
			}
			m.TakeAction(s, msg.Message, "Spam Filter (Edición)", detail, muteDur, nil)
			return
		}
	}

	for _, filter := range m.ScamFilters {
		match, _ := filter.FindStringMatch(content)
		if match != nil {
			detail := fmt.Sprintf("Posible estafa detectada en el texto.\nMatch: `%s`\nRegex: `%s`\n[Mensaje editado]", match.String(), filter.String())
			m.TakeAction(s, msg.Message, "Scam Phrase Filter (Edición)", detail, 0, nil)
			return
		}
	}
}

func (m *Manager) AnalyzeMessage(s BotSession, msg *discordgo.MessageCreate) {
	if msg.Author.Bot {
		return
	}

	if slices.Contains(msg.Member.Roles, os.Getenv("ADMIN_ID")) {
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
			muteDur := time.Duration(0)
			if filter.Mute {
				muteDur = 7 * 24 * time.Hour
			}
			m.TakeAction(s, msg.Message, "Spam Filter", detail, muteDur, nil)
			return
		}
	}

	for _, filter := range m.ScamFilters {
		match, _ := filter.FindStringMatch(content)
		if match != nil {
			detail := fmt.Sprintf("Posible estafa detectada en el texto.\nMatch: `%s`\nRegex: `%s`", match.String(), filter.String())
			m.TakeAction(s, msg.Message, "Scam Phrase Filter", detail, 0, nil)
			return
		}
	}

	if len(msg.Mentions) > 5 {
		m.TakeAction(s, msg.Message, "Mass Mention", "Demasiadas menciones en un solo mensaje.", 7*24*time.Hour, nil)
		return
	}

	if m.isSpamming(msg.GuildID, msg.Author.ID, msg.Content) {
		m.TakeAction(s, msg.Message, "Spam", "Enviando mensajes demasiado rápido.", 5*time.Minute, nil)
		return
	}

	// Detectar imágenes con nombres secuenciales (1.ext, 2.ext, 3.ext...)
	if isSequentialScamNaming(msg.Attachments) {
		m.KickAndPurge(s, msg.Message, "Imágenes Secuenciales Scam",
			"Imágenes nombradas secuencialmente detectadas (patrón de scam).", nil)
		return
	}

	// Solo analiza imágenes si hay 2 o más, a menos que sea un usuario nuevo/inactivo
	imgCount := 0
	for _, att := range msg.Attachments {
		if strings.HasPrefix(att.ContentType, "image/") {
			imgCount++
		}
	}

	isNewOrInactive := false
	m.mu.RLock()
	lastSeen, ok := m.LastActivity[msg.Author.ID]
	m.mu.RUnlock()

	if !ok {
		isNewOrInactive = true
	} else if time.Since(lastSeen) > 7*24*time.Hour {
		isNewOrInactive = true
	}

	if !isNewOrInactive && msg.Member != nil {
		joinedAt := msg.Member.JoinedAt
		if time.Since(joinedAt) < 7*24*time.Hour {
			isNewOrInactive = true
		}
	}

	shouldAnalyze := (isNewOrInactive && imgCount >= 1) || imgCount >= 2

	if shouldAnalyze {
		go func() {
			var once sync.Once
			for _, att := range msg.Attachments {
				if !strings.HasPrefix(att.ContentType, "image/") {
					continue
				}

				go func(attachment *discordgo.MessageAttachment) {
					img, err := DownloadImage(attachment.URL)
					if err == nil {
						start := time.Now()
						var mStart, mEnd runtime.MemStats
						runtime.ReadMemStats(&mStart)

						match, name, score, crop := m.Scanner.Compare(img)

						elapsed := time.Since(start)

						runtime.ReadMemStats(&mEnd)

						memUsedKB := int64(mEnd.HeapInuse-mStart.HeapInuse) / 1024
						if memUsedKB < 0 {
							memUsedKB = 0
						}

						if match {
							once.Do(func() {
								detail := fmt.Sprintf("Imagen detectada: %s\nScore: %.3f\nTiempo: %s\nMemoria: %s",
									name, score, elapsed, formatMemory(float64(memUsedKB)))
								m.KickAndPurge(s, msg.Message, ScamImageReason, detail, crop)
							})
							return
						}
					}

					if m.IsNSFWEnabled(msg.GuildID) {
						isNSFW, err := CheckNSFW(attachment.URL)
						if err == nil && isNSFW {
							var crop []byte
							if img != nil {
								var buf bytes.Buffer
								jpeg.Encode(&buf, img, &jpeg.Options{Quality: 60})
								crop = buf.Bytes()
							}
							once.Do(func() {
								m.TakeAction(s, msg.Message, "Contenido NSFW", "Imagen detectada como no segura para el servidor.", 7*24*time.Hour, crop)
							})
						}
					}
				}(att)
			}
		}()
	}

	m.mu.Lock()
	m.LastActivity[msg.Author.ID] = time.Now()
	m.mu.Unlock()
	go m.SaveActivity()
}

func formatMemory(b float64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", b/TB)
	case b >= GB:
		return fmt.Sprintf("%.2f GB", b/GB)
	case b >= MB:
		return fmt.Sprintf("%.2f MB", b/MB)
	case b >= KB:
		return fmt.Sprintf("%.2f KB", b/KB)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}

func (m *Manager) KickAndPurge(s BotSession, msg *discordgo.Message, reason, detail string, cropData []byte) {
	err := s.GuildMemberDelete(msg.GuildID, msg.Author.ID)
	if err != nil {
		fmt.Printf("Error kickeando usuario %s: %v\n", msg.Author.ID, err)
		return
	}

	channels, err := s.GuildChannels(msg.GuildID)
	if err == nil {
		for _, channel := range channels {
			if channel.Type != discordgo.ChannelTypeGuildText {
				continue
			}
			messages, err := s.ChannelMessages(channel.ID, 100, "", "", "")
			if err != nil {
				continue
			}
			var toDelete []string
			for _, m := range messages {
				if m.Author.ID == msg.Author.ID {
					toDelete = append(toDelete, m.ID)
				}
			}
			for i := 0; i < len(toDelete); i += 100 {
				end := i + 100
				if end > len(toDelete) {
					end = len(toDelete)
				}
				ids := toDelete[i:end]
				if len(ids) == 1 {
					s.ChannelMessageDelete(channel.ID, ids[0])
				} else if len(ids) > 0 {
					s.ChannelMessagesBulkDelete(channel.ID, ids)
				}
			}
		}
	}

	// También borra el mensaje original
	s.ChannelMessageDelete(msg.ChannelID, msg.ID)

	// Log
	logChannel := m.GetLogChannel(msg.GuildID)
	if logChannel != "" {
		embed := &discordgo.MessageEmbed{
			Title:       "🚨 Automod - Usuario Kickeado",
			Description: fmt.Sprintf("Usuario: <@%s> (%s) [%s]\nRazón: **%s**\nDetalle: %s\nAcción: Kickeado + mensajes eliminados", msg.Author.ID, msg.Author.String(), msg.Author.ID, reason, detail),
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

func (m *Manager) TakeAction(s BotSession, msg *discordgo.Message, reason, detail string, muteDuration time.Duration, cropData []byte) {
	s.ChannelMessageDelete(msg.ChannelID, msg.ID)

	if muteDuration > 0 {
		until := time.Now().Add(muteDuration)
		if err := s.GuildMemberTimeout(msg.GuildID, msg.Author.ID, &until); err != nil {
			fmt.Printf("Error muteando usuario %s: %v\n", msg.Author.ID, err)
		}
	}

	logChannel := m.GetLogChannel(msg.GuildID)
	if logChannel != "" {
		embed := &discordgo.MessageEmbed{
			Title:       "🚨 Automod",
			Description: fmt.Sprintf("Usuario: <@%s> (%s) [%s]\nRazón: **%s**\nDetalle: %s", msg.Author.ID, msg.Author.String(), msg.Author.ID, reason, detail),
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

func (m *Manager) isSpamming(guildID, userID string, content string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := guildID + ":" + userID
	now := time.Now()
	history := m.messageHistory[key]

	var newHistory []messageEntry
	duplicates := 0
	for _, entry := range history {
		if now.Sub(entry.Timestamp) < 5*time.Second {
			newHistory = append(newHistory, entry)
			if entry.Content == content {
				duplicates++
			}
		}
	}

	newHistory = append(newHistory, messageEntry{Content: content, Timestamp: now})
	m.messageHistory[key] = newHistory

	// Detectar 5 mensajes cualesquiera o 3 mensajes idénticos
	return len(newHistory) >= 5 || duplicates >= 2
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

func isSequentialScamNaming(attachments []*discordgo.MessageAttachment) bool {
	imgNames := make([]string, 0)
	for _, att := range attachments {
		if strings.HasPrefix(att.ContentType, "image/") {
			imgNames = append(imgNames, att.Filename)
		}
	}

	if len(imgNames) < 3 {
		return false
	}

	for i := 0; i < len(imgNames); i++ {
		name := imgNames[i]
		extIdx := strings.LastIndex(name, ".")
		if extIdx <= 0 {
			return false
		}
		prefix := name[:extIdx]
		if _, err := fmt.Sscanf(prefix, "%d", new(int)); err != nil {
			return false
		}
		for j := i + 1; j < len(imgNames); j++ {
			other := imgNames[j]
			otherExtIdx := strings.LastIndex(other, ".")
			if otherExtIdx <= 0 {
				return false
			}
			otherPrefix := other[:otherExtIdx]
			if _, err := fmt.Sscanf(otherPrefix, "%d", new(int)); err != nil {
				return false
			}
		}
	}

	return true
}
