package sshcleint

import (
	"bufio"
	"errors"
	"io"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

// CmdResults ...
type CmdResults struct {
	Cmd    string
	Result string
}

// TClinet is a Terminal Client
type TClient struct {

	// rh is Remote Host IP address
	rh       string
	CSession *ssh.Session
	Stdin    io.WriteCloser
	Stdout   io.Reader
}

// NewTClient creats a new TClient
func NewTClient(rh string, sshconfig *ssh.ClientConfig) (*TClient, error) {

	// Create a new TClient
	tc := new(TClient)

	// Dial to the remote-host
	client, err := ssh.Dial("tcp", rh+":22", sshconfig)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Create sesssion
	tc.CSession, err = client.NewSession()
	if err != nil {
		return nil, err
	}
	defer tc.CSession.Close()

	// Create StdIn/StOut
	tc.Stdin, err = tc.CSession.StdinPipe()
	if err != nil {
		return nil, err
	}

	tc.Stdout, err = tc.CSession.StdoutPipe()
	if err != nil {
		return nil, err
	}

	// Start remote shell
	err = tc.CSession.Shell()
	if err != nil {
		return nil, err
	}

	return tc, nil
}

// InsecureClientConfig ...
func InsecureClientConfig(userStr, passStr string) *ssh.ClientConfig {

	SSHconfig := &ssh.ClientConfig{
		User:    userStr,
		Timeout: 5 * time.Second,
		Auth:    []ssh.AuthMethod{ssh.Password(passStr)},

		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Config: ssh.Config{
			Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc",
				"aes256-cbc", "3des-cbc", "des-cbc"},
			KeyExchanges: []string{"diffie-hellman-group1-sha1",
				"diffie-hellman-group-exchange-sha1",
				"diffie-hellman-group14-sha1"},
		},
	}
	return SSHconfig
}

// ExecCmds ...
func (tc TClient) ExecCmds(initcmds, cmds []string) ([]CmdResults, error) {

	// Creating Output as String
	var output []CmdResults
	var strTmp string

	// Send the Initial Commands - no output is saved
	if len(initcmds) > 0 {
		for _, cmd := range initcmds {
			n, err := tc.Stdin.Write([]byte(cmd + "\n"))
			if err != nil {
				return nil, err
			}
			if n != len(cmd)-1 {
				str := "Command" + cmd + " has " + string(len(cmd)) + " bytes, but " + string(n) + " bytes sent"
				return nil, errors.New(str)
			}
		}
	}

	stdinLines := make(chan string)
	go func() {
		scanner := bufio.NewScanner(tc.Stdout)
		for scanner.Scan() {
			stdinLines <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			log.Printf("scanner failed: %v", err)
		}
		close(stdinLines)
	}()

	// Send the commands to the remotehost one by one.
	for i, cmd := range cmds {
		n, err := tc.Stdin.Write([]byte(cmd + "\n"))
		if err != nil {
			log.Fatal(err)
		}
		if i == len(cmds)-1 {
			_ = tc.Stdin.Close() // send eof
		}

		// Check if less byte is sent
		if n != len(cmd)-1 {
			str := "Command" + cmd + " has " + string(len(cmd)) + " bytes, but " + string(n) + " bytes sent"
			return nil, errors.New(str)
		}

		// wait for command to complete
		// we'll assume the moment we've gone 1 secs w/o any output that our command is done
		timer := time.NewTimer(0)
	InputLoop:
		for {
			timer.Reset(time.Second)
			select {
			case line, ok := <-stdinLines:
				if !ok {
					log.Println("Finished processing")
					break InputLoop
				}
				strTmp += line
				strTmp += "\n"
			case <-timer.C:
				break InputLoop
			}
		}
		output = append(output, CmdResults{cmd, strTmp})
		strTmp = ""
	}

	// Wait for session to finish
	err := tc.CSession.Wait()
	if err != nil {
		return nil, err
	}

	return output, nil
}
