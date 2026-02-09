from netmiko import ConnectHandler


class NetworkDevice:
    """Simple network device abstraction for Netmiko connections"""
    
    def __init__(self, hostname, device_type, username, password, session_log=None):
        self.hostname = hostname
        self.device_type = device_type
        self.username = username
        self.password = password
        self.session_log = session_log
        self.connection = None
    
    def connect(self):
        """Establish connection to the device"""
        self.connection = ConnectHandler(
            device_type=self.device_type,
            host=self.hostname,
            username=self.username,
            password=self.password,
            session_log=self.session_log
        )
    
    def disconnect(self):
        """Disconnect from the device"""
        if self.connection:
            self.connection.disconnect()
            self.connection = None
    
    def sendCommand(self, command, use_textfsm=False):
        """Send a command and return output"""
        if not self.connection:
            raise Exception(f"Not connected to {self.hostname}")
        return self.connection.send_command(command, use_textfsm=use_textfsm)
