package sshcleint

import (
	"bufio"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

// TClinet is a Terminal Client
type TClient struct {
}

// ExecCommands ...
func ExecCommands(rh string, commands []string, sshconfig *ssh.ClientConfig) ([]string, error) {

	// Gets IP, credentials and config/commands, SSH Config (Timeout, Ciphers, ...) and returns
	// output of the device as "string" and an error. If error == nil, means program was able to SSH with no issue

	// Creating Output as String
	var outputStr []string
	var strTmp string

	// Dial to the remote-host
	client, err := ssh.Dial("tcp", rh+":22", sshconfig)
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
	for i, cmd := range commands {
		_, err := stdin.Write([]byte(cmd + "\n"))
		if err != nil {
			log.Fatal(err)
		}
		if i == len(commands)-1 {
			_ = stdin.Close() // send eof
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
		outputStr = append(outputStr, strTmp)
		strTmp = ""
	}

	// Wait for session to finish
	err = session.Wait()
	if err != nil {
		return nil, err
	}

	return outputStr, nil
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
