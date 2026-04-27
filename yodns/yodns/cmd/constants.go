package cmd

const (
	// TagZF indicates that a domain originates from a zone file (CZDS or zone transfer)
	TagZF = "zf"

	// TagXen indicates that a domain originates from the xenon certificate transparency log.
	TagXen = "xen"

	// TagArg indicates that a domain originates from the argon certificate transparency log.
	TagArg = "arg"

	// TagNes indicates that a domain originates from the nessie certificate transparency log.
	TagNes = "nes"

	// TagYet indicates that a domain originates from the yeti certificate transparency log.
	TagYet = "yet"

	// TagOak indicates that a domain originates from the oak certificate transparency log.
	TagOak = "oak"

	// TagTa indicates that a domain originates from the trust asia certificate transparency log.
	TagTa = "ta"

	// TagNim indicates that a domain originates from the nimbus certificate transparency log.
	TagNim = "nim"

	// TagSab indicates that a domain originates from the sabre certificate transparency log.
	TagSab = "sab"

	// TagOdfr indicates that a domain originates from the open data effort of afnic.
	TagOdfr = "odfr"

	// TagOdsk indicates that a domain originates from the open data effort of sknic.
	TagOdsk = "odsk"

	// TagTra indicates that a domain originates from the tranco popularity list.
	TagTra = "tra"

	// TagUmb indicates that a domain originates from the umbrella popularity list.
	TagUmb = "umb"

	// TagMaj indicates that a domain originates from the majestic popularity list.
	TagMaj = "maj"

	// TagRad indicates that a domain originates from the radar popularity list.
	TagRad = "rad"

	// TagRescan indicates that a domain have been rescanned
	TagRescan = "rescan"
)

// SourceTags are tags that indicate the origin/source of a domain name.
// Contrary to for example positional tags (tra10k) or informational tags (rescan).
var SourceTags = map[string]any{
	TagZF:   nil,
	TagXen:  nil,
	TagArg:  nil,
	TagNes:  nil,
	TagYet:  nil,
	TagOak:  nil,
	TagTa:   nil,
	TagNim:  nil,
	TagSab:  nil,
	TagOdfr: nil,
	TagOdsk: nil,
	TagTra:  nil,
	TagUmb:  nil,
	TagMaj:  nil,
	TagRad:  nil,
}
