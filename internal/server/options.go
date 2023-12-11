package server

type Options struct {
	Address     string
	Datapath    string
	LoadPrivkey bool
	PrivKeyPath string
	PubKeyPath  string
	SavePubKey  bool
	SavePrivKey bool
}

func NewDefaultOptions() *Options {
	return &Options{
		Address:     "0.0.0.0",
		Datapath:    "./testFiles/",
		LoadPrivkey: false,
		SavePrivKey: false,
		SavePubKey:  true,
		PubKeyPath:  "pubkey.pem",
	}
}
