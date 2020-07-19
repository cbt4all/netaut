package sshcleint

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// Gets IP, credentials and config/commands and then applies on the given IP (SSH)
// Working but to fix

// ExecCommandsSSH ...
func ExecCommandsSSH(ip string, initcmds []string, commands []string, d time.Duration,
	lg bool, sshconfig *ssh.ClientConfig) (string, error) {

	// Gets IP, credentials and config/commands, SSH Config (Timeout, Ciphers, ...) and returns
	// output of the device as "string" and an error. If error == nil, means program was able to SSH with no issue

	// Vars
	//---------------
	// ip is the IP address of the device you trying to login to
	// initcmds is Initial Commands. Some devices need one or more initial command(s) to enable some features (e.g. "set cli op-command-xml-output on" for Palo Alto)
	// commands is the list of the commands that shoud be run
	// errlgr, tcklgr are Error Logger and Tracker Logger
	// d is time.Duration used in time.Sleep()
	// lg means log? yes/no: if lg == true, ExecCommandsSSH print the executed command in terminal

	// Creating outerr as Output Error.
	outerr := errors.New("nil")
	outerr = nil

	// Creating Output as String
	var outputStr string

	// Dial SSH to the device
	client, err := ssh.Dial("tcp", ip+":22", sshconfig)
	if err != nil {
		outerr = err
		return "", outerr
	}
	defer client.Close()

	// Create sesssion
	session, err := client.NewSession()
	if err != nil {
		outerr = err
		return "", outerr
	}
	defer session.Close()

	// StdinPipe() and StdoutPipe() follows io.Pipe() concept. What is written in stdin (as Writer)
	// can be read from stdout (as Reader). The idea is I send commands by stdin and see the result (SSH ouput) in stdout
	//
	// StdinPipee() returns a pipe that will be connected to the remote command's standard input when the command starts.
	// StdoutPipe() returns a pipe that will be connected to the remote command's standard output when the command starts.
	// If the StdoutPipe reader is not serviced fast enough it may eventually cause the remote command to block.
	stdin, err := session.StdinPipe()
	if err != nil {
		outerr = err
		return "", outerr
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		outerr = err
		return "", outerr
	}

	// Start remote shell
	err = session.Shell()
	if err != nil {
		outerr = err
		return "", outerr
	}
	//----------------------------------------------------------------------------

	// Enable Password -> Feature work
	//---------------

	// Tried to detect if the device needs Enable Password, in a for-loop, wasn't sucessful
	// so here just put enable password
	//fmt.Fprintf(stdin, "\n")
	//fmt.Fprintf(stdin, "%s\n", "enable")
	//fmt.Fprintf(stdin, "%s\n", enPassStr)

	//Send the commands.
	//---------------

	// Send initial command(s)
	for _, cmd := range initcmds {

		n, err := stdin.Write([]byte(cmd + "\n"))
		if err != nil {
			outerr = err
			return "", outerr
		}

		// Error handeling: Check the number of byte is sent
		if n-1 != len(cmd) {
			tmpStr := `For the IP` + ip + `The command "` + cmd + `" is ` +
				strconv.Itoa(len(cmd)) + ` byte but ` + strconv.Itoa(n) + ` byte is sent to the device`
			outerr = errors.New(tmpStr)
			return "", outerr
		}

		if lg {
			fmt.Println(cmd)
		}
	}

	// Send main command(s)
	// In the config file, two Enter should be after the command Write
	// also and the command Exit should be the last command
	for _, cmd := range commands {

		n, err := stdin.Write([]byte(cmd + "\n"))
		if err != nil {
			outerr = err
			return "", outerr
		}

		// Error handeling: Check the number of byte is sent
		if n-1 != len(cmd) {
			tmpStr := `For the IP` + ip + `The command "` + cmd + `" is ` +
				strconv.Itoa(len(cmd)) + ` byte but ` + strconv.Itoa(n) + ` byte is sent to the device`
			outerr = errors.New(tmpStr)
			return "", outerr
		}

		if lg {
			fmt.Println(cmd)
		}

		//Make it slow
		time.Sleep(d)
	}

	// Send exit command
	stdin.Write([]byte("exit" + "\n"))
	if lg {
		fmt.Println("exit")
	}

	// Wait for session to finish
	err = session.Wait()
	if err != nil {
		outerr = err
		return "", outerr
	}

	// Reading output
	strByte, _ := ioutil.ReadAll(stdout)
	outputStr = string(strByte)

	return outputStr, outerr
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
