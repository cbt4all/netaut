package sshcleint

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// CmdResults ..
type CmdResults struct {
	Cmd    string
	Result string
}

// RhConfig remote-host config
type RhConfig struct {
	rh       string
	protocol string
	port     string
}

// CreateRhConfig ...
func CreateRhConfig(rh, protocol, port string) RhConfig {

	rhc := RhConfig{
		rh,
		protocol,
		port,
	}
	return rhc
}

// InsecureClientConfig ...
func InsecureClientConfig(userStr, passStr string, t time.Duration) *ssh.ClientConfig {

	SSHconfig := &ssh.ClientConfig{
		User:    userStr,
		Timeout: t,
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

// ExecCommands uses ssh.Dial to dials to remote-host, applies what is mentioned in 'initcmds' as initial commands, then 'cmds' as commands. This function needs
// remote-host IP, protocol and port which gets from RhConfig and also ssh.ClientConfig
// It returns a CmdResults
func ExecCommands(rhc RhConfig, initcmds, cmds []string, sshconfig *ssh.ClientConfig) ([]CmdResults, error) {

	// Creating Output as String
	var output []CmdResults
	var strTmp string

	// Dial to the remote-host
	client, err := ssh.Dial(rhc.protocol, rhc.rh+":"+rhc.port, sshconfig)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create sesssion
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}

	// Start remote shell
	err = session.Shell()
	if err != nil {
		return nil, err
	}

	// Send the Initial Commands - no output is saved
	if len(initcmds) > 0 {
		for i, cmd := range initcmds {

			n, err := stdin.Write([]byte(cmd + "\n"))
			if err != nil {
				fmt.Println(i, cmd)
				return nil, err
			}

			// Check if the entire command is sent properly
			if n != len(cmd)+1 {
				str := "Command " + cmd + " has " + strconv.Itoa(len(cmd)) + " bytes, but " + strconv.Itoa(n) + " bytes sent"
				return nil, errors.New(str)
			}
		}
	}

	stdinLines := make(chan string)
	go func() {
		scanner := bufio.NewScanner(stdout)
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
		n, err := stdin.Write([]byte(cmd + "\n"))
		if err != nil {
			log.Fatal(err)
		}
		if i == len(cmds)-1 {
			_ = stdin.Close() // send eof
		}

		// Check if the entire command is sent properly
		if n != len(cmd)+1 {
			str := "Command " + cmd + " has " + strconv.Itoa(len(cmd)) + " bytes, but " + strconv.Itoa(n) + " bytes sent"
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
	err = session.Wait()
	if err != nil {
		return nil, err
	}

	return output, nil
}
