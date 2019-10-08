package jwt

type Config struct {
	Secret string `toml:"secret"`
	Lifetime int `toml:"lifetime"`
}
