// Command Talon performs password-guessing attacks and user enumeration against
// Active Directory over Kerberos and LDAP.
//
// This is the ZerkerEOD maintenance fork of Tylous/Talon (upstream is no longer
// maintained). See README.md for the relationship to upstream.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ZerkerEOD/Talon/internal/auth"
	"github.com/ZerkerEOD/Talon/internal/config"
	"github.com/ZerkerEOD/Talon/internal/input"
	"github.com/ZerkerEOD/Talon/internal/spray"
)

const banner = `
  __________  ________  ___       ________  ________
  |\___    _\\\   __  \|\  \     |\   __  \|\   ___  \
  \|___ \  \_\ \  \|\  \ \  \    \ \  \|\  \ \  \\ \  \
       \ \  \ \ \   __  \ \  \    \ \  \\\  \ \  \\ \  \
        \ \  \ \ \  \ \  \ \  \____\ \  \\\  \ \  \\ \  \
         \ \__\ \ \__\ \__\ \_______\ \_______\ \__\\ \__\
          \|__|  \|__|\|__|\|_______|\|_______|\|__| \|__|
                              (@Tyl0us, fork: ZerkerEOD)

        Version: 4.0.0
`

func main() {
	opt := config.Parse()
	fmt.Print(banner)

	reader := bufio.NewReader(os.Stdin)

	// ---- validation ----
	if opt.Kerb && opt.LDAP {
		log.Fatal("Error: Please choose Kerberos (-K) or LDAP (-L), not both")
	}
	if opt.Enum && opt.LDAP {
		log.Fatal("Error: Enumeration (-E) uses Kerberos; it cannot be combined with -L")
	}
	if opt.Host == "" && opt.Hostfile == "" {
		log.Fatal("Error: Please provide a host (-H) or a list of hosts (-Hostfile)")
	}
	if opt.User == "" && opt.Userfile == "" {
		log.Fatal("Error: Please provide a username (-U) or a list of usernames (-Userfile)")
	}
	if !opt.Enum && opt.Pass == "" && opt.Passfile == "" {
		log.Fatal("Error: Please provide a password (-P / -Passfile) or select enumeration (-E)")
	}
	if opt.Pass != "" && opt.Passfile != "" {
		log.Fatal("Error: Please provide either a single password (-P) or a list (-Passfile), not both")
	}

	// ---- load inputs ----
	hosts := loadList("host", opt.Host, opt.Hostfile)
	if len(hosts) == 0 {
		log.Fatal("Error: no usable hosts found")
	}
	usernames := loadList("user", opt.User, opt.Userfile)
	if len(usernames) == 0 {
		log.Fatal("Error: no usable usernames found")
	}

	// ---- services, mode, passwords ----
	var services []string
	mode := auth.EnumOff
	switch {
	case opt.Enum:
		services = []string{"KERB"}
		if opt.Aggressive {
			mode = auth.EnumAggressive
		} else {
			mode = auth.EnumSafe
		}
	case opt.Kerb:
		services = []string{"KERB"}
	case opt.LDAP:
		services = []string{"LDAP"}
	default:
		services = []string{"KERB", "LDAP"}
	}

	var passwords []string
	switch {
	case opt.Enum:
		passwords = []string{""}
	case opt.Pass != "":
		passwords = []string{opt.Pass}
	default:
		passwords = loadList("password", "", opt.Passfile)
		if len(passwords) == 0 {
			log.Fatal("Error: no usable passwords found in -Passfile")
		}
	}

	// ---- consent for destructive modes ----
	if opt.Passfile != "" {
		confirm(reader, "[*] Warning: spraying multiple passwords risks locking accounts. Continue? [y/n]: ")
	}
	if mode == auth.EnumAggressive {
		confirm(reader, "[*] Warning: aggressive enumeration (-Eagg) submits pre-authentication and CAN lock accounts. Continue? [y/n]: ")
	}

	if mode != auth.EnumSafe && opt.Threshold == 0 {
		fmt.Println("[*] Note: -Threshold not set; per-user lockout budget is not enforced. " +
			"Relying on -A pacing and the lockout-rate detector. Pass -Threshold <n> for per-account protection.")
	}

	// ---- run ----
	st := spray.NewState(usernames, int(opt.Attempts), opt.Threshold, int(opt.LockErr))
	defer func() {
		summary := st.Summary()
		fmt.Print(summary)
		if opt.OutFile != "" {
			if f, err := os.OpenFile(opt.OutFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.WriteString(summary)
				_ = f.Close()
			}
		}
	}()

	spray.Run(opt, st, hosts, services, passwords, mode)
}

// loadList merges an optional single value and an optional file into one list.
func loadList(kind, single, file string) []string {
	var out []string
	if file != "" {
		config.Debugf("Reading %s file %s\n", kind, file)
		lines, err := input.Lines(file)
		if err != nil {
			log.Fatalf("Error reading %s file %s: %v", kind, file, err)
		}
		out = append(out, lines...)
	}
	if single != "" {
		out = append(out, strings.TrimSpace(single))
	}
	return out
}

func confirm(reader *bufio.Reader, prompt string) {
	fmt.Print(prompt)
	text, _ := reader.ReadString('\n')
	if !strings.Contains(strings.ToLower(text), "y") {
		fmt.Println("[*] Shutting down")
		os.Exit(0)
	}
	fmt.Print("\n")
}
