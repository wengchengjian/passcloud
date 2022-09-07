# Passcloud

## Description
Passcloud is a simple password management tool. It is mainly used to learn the use of rust, and its special function is cloud storage

### Install

#### For Rust Developer

##### Cargo Install
```
  Cargo install --git https://github.com/wengchengjian/passcloud.git
```
#### Or Git Clone And Build Likely
```
  git clone https://github.com/wengchengjian/passcloud.git
  
  cd /passcloud
  
  cargo install --path .
```

#### Configure

##### Win

###### Cmd
```
  setx /m PASS_HOME "What you expect Directory"
```
##### Linux
Append the text `export PASS_HOME="What you expect Directory"` to the end of file which at /etc/profile
And refresh profile file use cmd `source /etc/profile`

##### Configure Passcloud Setting

>Note: The following commands are not mandatory If you just want to store your password locally

Make sure you installed successful And execute follow command:
```shell
    # configure your account and password
    passcloud config -u username -p password
    # configure your address for server to start server
    passcloud config --address 'local-address'
    # configure your cloud-address for client to connected server address
    passcloud config --cloud-address 'server-address'
```

#### Server Start
>Note: Check your config has contains server address
```shell
    passcloud server start
```
#### Client Command
>Note: Check your config has contains Account and cloud-address
```shell
    # connect to server firstly
    passcloud client register
     
    # push local passwords to server
    passcloud client push
    
    # pull remote passwords to local
    passcloud client pull
    
    # stop connected server. this way will not shutdown server immediately
    passcloud client stop
```
#### Basic Usage
>Note: Make sure you have configured PASS_HOME
##### Acquire password
```shell
    # Get the password list of the specified key under an app.
    passcloud get app key
    # or only acquire the latest password for key
    passcloud get app key --last
```
##### Set password
```shell
    # Set the password of the specified key under an app.
    passcloud set app key password
```
##### Automatically generate password
```shell
    # generate the password  of the specified key under an app.
    passcloud gen app key
    
    # use custom length to generate the password  of the specified key under an app.
    passcloud gen app key -l 12
```

##### Automatically generate password
```shell
    # generate the password  of the specified key under an app.
    passcloud gen app key
    
    # use custom length to generate the password  of the specified key under an app.
    passcloud gen app key -l 12
```

##### More Command
`passcloud --help`

#### Future plans

- More friendly password generation
- Use encryption for communication between Passcloud C/S
- More friendly command
- Add more ways to install Passcloud
