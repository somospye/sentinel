package automod

import (
	"strings"

	"github.com/dlclark/regexp2"
)

type IFilter struct {
	Filter      *regexp2.Regexp
	Mute        bool
	WarnMessage string
}

const LINK_SOSPECHOSO = "🚫 Enlace sospechoso."
const SPAM_BOT = "🚫 Spam bot."

func PhraseToSpamRegex(phrase string) *regexp2.Regexp {
	sep := `[\s\W_]*`
	numberPattern := `\$?\s*(?:\d{1,3}(?:[.,]\d{3})+|\d+(?:[.,]\d+)?)(?:\s*[kKmMbB])?`

	reToken := regexp2.MustCompile(`(\$number)|[^\s]+`, 0)

	var tokens []string
	match, _ := reToken.FindStringMatch(phrase)
	for match != nil {
		tokens = append(tokens, match.String())
		match, _ = reToken.FindNextMatch(match)
	}

	var parts []string
	for _, token := range tokens {
		if strings.EqualFold(token, "$number") {
			parts = append(parts, numberPattern)
		} else {
			var chars []string
			for _, ch := range token {
				chars = append(chars, regexp2.Escape(string(ch)))
			}
			parts = append(parts, strings.Join(chars, sep))
		}
	}

	body := strings.Join(parts, sep)
	// Use IgnoreCase flag instead of (?i) prefix for reliability
	return regexp2.MustCompile(`\b(?:`+body+`)\b`, regexp2.IgnoreCase)
}

func WordPermutations(s string) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	if len(words) == 1 {
		return []string{words[0]}
	}

	var result []string
	var backtrack func(path []string, used []bool)
	backtrack = func(path []string, used []bool) {
		if len(path) == len(words) {
			result = append(result, strings.Join(path, " "))
			return
		}

		seen := make(map[string]bool)
		for i := 0; i < len(words); i++ {
			if used[i] || seen[words[i]] {
				continue
			}
			seen[words[i]] = true
			used[i] = true
			backtrack(append(path, words[i]), used)
			used[i] = false
		}
	}

	backtrack(nil, make([]bool, len(words)))
	return result
}

var BasePhrases = []string{
	"free bonus code",
	"crypto casino",
	"receive your $number",
	"belowex",
	"evencas",
	"special promo code",
	"bonus instantly",
	"deleted one hour",
	"claim your reward",
	"free gift code",
	"take your free reward",
	"free nitro",
	"free nitro click here",
	"free discord nitro",
	"claim your nitro",
}

func GetScamFilterList() []*regexp2.Regexp {
	var filters []*regexp2.Regexp
	uniquePhrases := make(map[string]bool)

	for _, p := range BasePhrases {
		perms := WordPermutations(p)
		for _, perm := range perms {
			if !uniquePhrases[perm] {
				uniquePhrases[perm] = true
				filters = append(filters, PhraseToSpamRegex(perm))
			}
		}
	}
	return filters
}

var SpamFilterList = []IFilter{
	{Filter: regexp2.MustCompile(`https?://[\w.-]+\.xyz($|\W)`, regexp2.IgnoreCase), Mute: false, WarnMessage: LINK_SOSPECHOSO},
	{Filter: regexp2.MustCompile(`https?://[\w.-]+\.click($|\W)`, regexp2.IgnoreCase), Mute: false, WarnMessage: LINK_SOSPECHOSO},
	{Filter: regexp2.MustCompile(`https?://[\w.-]+\.info($|\W)`, regexp2.IgnoreCase), Mute: false, WarnMessage: LINK_SOSPECHOSO},
	{Filter: regexp2.MustCompile(`https?://[\w.-]+\.ru($|\W)`, regexp2.IgnoreCase), Mute: false, WarnMessage: LINK_SOSPECHOSO},
	{Filter: regexp2.MustCompile(`https?://[\w.-]+\.biz($|\W)`, regexp2.IgnoreCase), Mute: false, WarnMessage: LINK_SOSPECHOSO},
	{Filter: regexp2.MustCompile(`https?://[\w.-]+\.online($|\W)`, regexp2.IgnoreCase), Mute: false, WarnMessage: LINK_SOSPECHOSO},
	{Filter: regexp2.MustCompile(`https?://[\w.-]+\.club($|\W)`, regexp2.IgnoreCase), Mute: false, WarnMessage: LINK_SOSPECHOSO},
	{Filter: regexp2.MustCompile(`(https?://)?(t\.me|telegram\.me|wa\.me|whatsapp\.me)/.+`, regexp2.IgnoreCase), Mute: true},
	{Filter: regexp2.MustCompile(`(https?://)?(pornhub|xvideos|xhamster|xnxx|hentaila)(\.\S+)+/`, regexp2.IgnoreCase), Mute: true},
	{Filter: regexp2.MustCompile(`(?!(https?://)?discord\.gg/programacion$)(https?://)?discord\.gg/\w+`, regexp2.IgnoreCase), Mute: false},
	{Filter: regexp2.MustCompile(`(?!(https?://)?discord\.com/invite/programacion$)(https?://)?discord\.com/invite/.+`, regexp2.IgnoreCase), Mute: true},
	{Filter: regexp2.MustCompile(`(https?://)?multiigims.netlify.app`, regexp2.IgnoreCase), Mute: true},
	{Filter: regexp2.MustCompile(`\[.*?steamcommunity\.com/.*\]`, regexp2.IgnoreCase), Mute: true},
	{Filter: regexp2.MustCompile(`https?://(www\.)?\w*solara\w*\.\w+/?`, regexp2.IgnoreCase), Mute: true, WarnMessage: SPAM_BOT},
	{Filter: regexp2.MustCompile(`(?:solara|wix)(?=.*\broblox\b)(?=.*(?:executor|free)).*`, regexp2.IgnoreCase|regexp2.Singleline), Mute: true, WarnMessage: SPAM_BOT},
	{Filter: regexp2.MustCompile(`(?:https?://(?:www\.)?|www\.)?outlier\.ai\b`, regexp2.IgnoreCase), Mute: true, WarnMessage: SPAM_BOT},
	{Filter: regexp2.MustCompile(`(?=.*\b(eth|ethereum|btc|bitcoin|capital|crypto|memecoins|nitro|\$|nsfw)\b)(?=.*\b(gana\w*|gratis|multiplica\w*|inver\w*|giveaway|server|free|earn)\b)`, regexp2.IgnoreCase|regexp2.Singleline), Mute: false, WarnMessage: "Posible estafa detectada"},
}
