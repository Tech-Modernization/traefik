package acme

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/xenolf/lego/acme"
)

func TestDomainsSet(t *testing.T) {
	checkMap := map[string]Domains{
		"":                                   {},
		"foo.com":                            {Domain{Main: "foo.com", SANs: []string{}}},
		"foo.com,bar.net":                    {Domain{Main: "foo.com", SANs: []string{"bar.net"}}},
		"foo.com,bar1.net,bar2.net,bar3.net": {Domain{Main: "foo.com", SANs: []string{"bar1.net", "bar2.net", "bar3.net"}}},
	}
	for in, check := range checkMap {
		ds := Domains{}
		ds.Set(in)
		if !reflect.DeepEqual(check, ds) {
			t.Errorf("Expected %+v\nGot %+v", check, ds)
		}
	}
}

func TestDomainsSetAppend(t *testing.T) {
	inSlice := []string{
		"",
		"foo1.com",
		"foo2.com,bar.net",
		"foo3.com,bar1.net,bar2.net,bar3.net",
	}
	checkSlice := []Domains{
		{},
		{
			Domain{
				Main: "foo1.com",
				SANs: []string{}}},
		{
			Domain{
				Main: "foo1.com",
				SANs: []string{}},
			Domain{
				Main: "foo2.com",
				SANs: []string{"bar.net"}}},
		{
			Domain{
				Main: "foo1.com",
				SANs: []string{}},
			Domain{
				Main: "foo2.com",
				SANs: []string{"bar.net"}},
			Domain{Main: "foo3.com",
				SANs: []string{"bar1.net", "bar2.net", "bar3.net"}}},
	}
	ds := Domains{}
	for i, in := range inSlice {
		ds.Set(in)
		if !reflect.DeepEqual(checkSlice[i], ds) {
			t.Errorf("Expected  %s %+v\nGot %+v", in, checkSlice[i], ds)
		}
	}
}

func TestCertificatesRenew(t *testing.T) {
	domainsCertificates := DomainsCertificates{
		lock: sync.RWMutex{},
		Certs: []*DomainsCertificate{
			{
				Domains: Domain{
					Main: "foo1.com",
					SANs: []string{}},
				Certificate: &Certificate{
					Domain:        "foo1.com",
					CertURL:       "url",
					CertStableURL: "url",
					PrivateKey: []byte(`
REDACTED_SECRET
`),
					Certificate: []byte(`
-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIJAK78ukR/Qu4rMA0GCSqGSIb3DQEBBQUAMBMxETAPBgNV
BAMMCGZvbzEuY29tMB4XDTE2MDYxOTIyMDMyM1oXDTI2MDYxNzIyMDMyM1owEzER
MA8GA1UEAwwIZm9vMS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDo6ocZ3AbLbT7clzP0iB83ghHfbZfYeHCTqfweyz9azsV5Nmg+9dby4d4jVuZA
mzL0LrGjeh3M7rijumuAxmXl4PDl+TWaZSKPcneczeDC1z8Jz7wANcaV1q4BJ0cE
VNG9ZCB7Q+/9DlTR/IvZUIehH2Ya/gJDudE0o+6zS9gkxtehNs7zPiwhs3Pc6/2j
8cYxFvwPSs09Mx0Lra0dJuI7VSjEtev11wE4a3vzoCyJFMnxur0YJVCDN3RZ+1vz
Pp11bZi5auYTGWQd18LigbQPlJTVAHiV0/KXt+FVaV8fALU1f5xGcNIR5iQBx2+8
h6R0z/If7PrZeHBOgzQT1MLPAgMBAAGjUDBOMB0GA1UdDgQWBBRFLH1wF6BT51uq
yWNqBnCrPFIglzAfBgNVHSMEGDAWgBRFLH1wF6BT51uqyWNqBnCrPFIglzAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAr7aH3Db6TeAZkg4Zd7SoF2q11
erzv552PgQUyezMZcRBo2q1ekmUYyy2600CBiYg51G+8oUqjJKiKnBuaqbMX7pFa
FsL7uToZCGA57cBaVejeB+p24P5bxoJGKCMeZcEBe5N93Tqu5WBxNEX7lQUo6TSs
gSN2Olf3/grNKt5V4BduSIQZ+YHlPUWLTaz5B1MXKSUqjmabARP9lhjO14u9USvi
dMBDFskJySQ6SUfz3fyoXELoDOVbRZETuSodpw+aFCbEtbcQCLT3A0FG+BEPayZH
tt19zKUlr6e+YFpyjQPGZ7ZkY7iMgHEkhKrXx2DiZ1+cif3X1xfXWQr0S5+E
-----END CERTIFICATE-----
`),
				},
			},
			{
				Domains: Domain{
					Main: "foo2.com",
					SANs: []string{}},
				Certificate: &Certificate{
					Domain:        "foo2.com",
					CertURL:       "url",
					CertStableURL: "url",
					PrivateKey: []byte(`
REDACTED_SECRET
`),
					Certificate: []byte(`
-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIJAK25/Z9Jz6IBMA0GCSqGSIb3DQEBBQUAMBMxETAPBgNV
BAMMCGZvbzIuY29tMB4XDTE2MDYyMDA5MzUyNloXDTI2MDYxODA5MzUyNlowEzER
MA8GA1UEAwwIZm9vMi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDushW5KtncV9heFHeppbB9VyCKopL//JcXM2qQlLqbP2dEI1OU9rC+sIUhEp1H
tQ7vEPsDlVNxusY4BpO+sRofuYH/gUYv6A3gCJNtUWkpeeABgRYDf//N4FntdRJZ
pD4I0L6Xv3ol6gO9AP74rAKR7itUPWkY3WGlUR4aHDPIo5g8oujj4AZV7UsVbDhT
+/wiKXX+AEF6FkEgu6EBKlfLhbXfYsk+Xvr8RsaqHSdXPZSUWpQdHE77ZTZtrhgi
kj7T9U5D0Kr9PMdJR1NMt8EcT9Bv5oMF+m0xZNG8CeAupSCU5xkWLpICWPESQk7r
Ppu2ahVRaygoGlsgcMLn751nAgMBAAGjUDBOMB0GA1UdDgQWBBQ6FZWqB9qI4NN+
2jFY6xH8uoUTnTAfBgNVHSMEGDAWgBQ6FZWqB9qI4NN+2jFY6xH8uoUTnTAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQCRhuf2dQhIEOmSOGgtRELF2wB6
NWXt0lCty9x4u+zCvITXV8Z0C34VQGencO3H2bgyC3ZxNpPuwZfEc2Pxe8W6bDc/
OyLckk9WLo00Tnr2t7rDOeTjEGuhXFZkhIbJbKdAH8cEXrxKR8UXWtZgTv/b8Hv/
g6tbeH6TzBsdMoFtUCsyWxygYwnLU+quuYvE2s9FiCegf2mdYTCh/R5J5n/51gfB
uC+NakKMfaCvNg3mOAFSYC/0r0YcKM/5ldKGTKTCVJAMhnmBnyRc/70rKkVRFy2g
iIjUFs+9aAgfCiL0WlyyXYAtIev2gw4FHUVlcT/xKks+x8Kgj6e5LTIrRRwW
-----END CERTIFICATE-----
`),
				},
			},
		},
	}

	newCertificate := &Certificate{
		Domain:        "foo1.com",
		CertURL:       "url",
		CertStableURL: "url",
		PrivateKey: []byte(`
REDACTED_SECRET
`),
		Certificate: []byte(`
-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIJAPQiOiQcwYaRMA0GCSqGSIb3DQEBBQUAMBMxETAPBgNV
BAMMCGZvbzEuY29tMB4XDTE2MDYxOTIyMTE1NFoXDTI2MDYxNzIyMTE1NFowEzER
MA8GA1UEAwwIZm9vMS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDU51K5crbN5It/RSqCsjimOSlqqGtr76md1rguLiNejXnWy+JKfsNLKck6irWN
t9EkCjIOHGwELhLhG4PnhTl6UnjAs9leYdGy9v43CIez1WYOrC4i3bVu26p40x5u
RpvlycOcLooq58yFdFxECWW5hfIKRB7/434uVRB3omzfhOLEymR5A5fj85WuiRLJ
VGciri76jRR97vPn7jVZUfre1zLsfCLvbjhotTNkKz5BBrYPDp+oTCNuiev3vh8z
rxTEONNkRDL27bjIPNqOEMGnU5MACSWHtT6WLeD11LI1UEVeoS6dbZ/IG8up4k5J
OKGp9ysAIH9hiFg5f3i8xcQtAgMBAAGjUDBOMB0GA1UdDgQWBBQPfkS5ehpstmSb
8CGJE7GxSCxl2DAfBgNVHSMEGDAWgBQPfkS5ehpstmSb8CGJE7GxSCxl2DAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQA99A+itS9ImdGRGgHZ5fSusiEq
wkK5XxGyagL1S0f3VM8e78VabSvC0o/xdD7DHVg6Az8FWxkkksH6Yd7IKfZZUzvs
kXQhlOwWpxgmguSmAs4uZTymIoMFRVj3nG664BcXkKu4Yd9UXKNOWP59zgvrCJMM
oIsmYiq5u0MFpM31BwfmmW3erqIcfBI9OJrmr1XDzlykPZNWtUSSfVuNQ8d4bim9
XH8RfVLeFbqDydSTCHIFvYthH/ESbpRCiGJHoJ8QLfOkhD1k2fI0oJZn5RVtG2W8
bZME3gHPYCk1QFZUptriMCJ5fMjCgxeOTR+FAkstb/lTRuCc4UyILJguIMar
-----END CERTIFICATE-----
`),
	}

	err := domainsCertificates.renewCertificates(
		newCertificate,
		Domain{
			Main: "foo1.com",
			SANs: []string{}})
	if err != nil {
		t.Errorf("Error in renewCertificates :%v", err)
	}
	if len(domainsCertificates.Certs) != 2 {
		t.Errorf("Expected domainsCertificates length %d %+v\nGot %+v", 2, domainsCertificates.Certs, len(domainsCertificates.Certs))
	}
	if !reflect.DeepEqual(domainsCertificates.Certs[0].Certificate, newCertificate) {
		t.Errorf("Expected new certificate %+v \nGot %+v", newCertificate, domainsCertificates.Certs[0].Certificate)
	}
}

func TestNoPreCheckOverride(t *testing.T) {
	acme.PreCheckDNS = nil // Irreversable - but not expecting real calls into this during testing process
	err := dnsOverrideDelay(0)
	if err != nil {
		t.Errorf("Error in dnsOverrideDelay :%v", err)
	}
	if acme.PreCheckDNS != nil {
		t.Errorf("Unexpected change to acme.PreCheckDNS when leaving DNS verification as is.")
	}
}

func TestSillyPreCheckOverride(t *testing.T) {
	err := dnsOverrideDelay(-5)
	if err == nil {
		t.Errorf("Missing expected error in dnsOverrideDelay!")
	}
}

func TestPreCheckOverride(t *testing.T) {
	acme.PreCheckDNS = nil // Irreversable - but not expecting real calls into this during testing process
	err := dnsOverrideDelay(5)
	if err != nil {
		t.Errorf("Error in dnsOverrideDelay :%v", err)
	}
	if acme.PreCheckDNS == nil {
		t.Errorf("No change to acme.PreCheckDNS when meant to be adding enforcing override function.")
	}
}

func TestAcmeClientCreation(t *testing.T) {
	acme.PreCheckDNS = nil // Irreversable - but not expecting real calls into this during testing process
	// Lengthy setup to avoid external web requests - oh for easier golang testing!
	account := &Account{Email: "f@f"}
	account.PrivateKey, _ = base64.StdEncoding.DecodeString(`
MIIBPAIBAAJBAMp2Ni92FfEur+CAvFkgC12LT4l9D53ApbBpDaXaJkzzks+KsLw9zyAxvlrfAyTCQ
7tDnEnIltAXyQ0uOFUUdcMCAwEAAQJAK1FbipATZcT9cGVa5x7KD7usytftLW14heQUPXYNV80r/3
lmnpvjL06dffRpwkYeN8DATQF/QOcy3NNNGDw/4QIhAPAKmiZFxA/qmRXsuU8Zhlzf16WrNZ68K64
asn/h3qZrAiEA1+wFR3WXCPIolOvd7AHjfgcTKQNkoMPywU4FYUNQ1AkCIQDv8yk0qPjckD6HVCPJ
llJh9MC0svjevGtNlxJoE3lmEQIhAKXy1wfZ32/XtcrnENPvi6lzxI0T94X7s5pP3aCoPPoJAiEAl
cijFkALeQp/qyeXdFld2v9gUN3eCgljgcl0QweRoIc=---`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
"new-authz": "https://foo/acme/new-authz",
"new-cert": "https://foo/acme/new-cert",
"new-reg": "https://foo/acme/new-reg",
"revoke-cert": "https://foo/acme/revoke-cert"
}`))
	}))
	defer ts.Close()
	a := ACME{DNSProvider: "manual", DelayDontCheckDNS: 10, CAServer: ts.URL}

	client, err := a.buildACMEClient(account)
	if err != nil {
		t.Errorf("Error in buildACMEClient: %v", err)
	}
	if client == nil {
		t.Errorf("No client from buildACMEClient!")
	}
	if acme.PreCheckDNS == nil {
		t.Errorf("No change to acme.PreCheckDNS when meant to be adding enforcing override function.")
	}
}
