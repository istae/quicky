# $socket = new-object System.Net.Sockets.UdpClient("localhost", 9999)
# $socket.Send()

# $writer = new-object System.IO.StreamWriter $stream
# $writer.Write("hello")
# $writer.Flush()



[int] $Port = 9999 
$IP = "127.0.0.1" 
$Address = [system.net.IPAddress]::Parse($IP) 

# Create IP Endpoint 
$End = New-Object System.Net.IPEndPoint $address, $port 

# Create Socket 
$Saddrf   = [System.Net.Sockets.AddressFamily]::InterNetwork 
$Stype    = [System.Net.Sockets.SocketType]::Dgram 
$Ptype    = [System.Net.Sockets.ProtocolType]::UDP 
$Sock     = New-Object System.Net.Sockets.Socket $saddrf, $stype, $ptype 
$Sock.TTL = 26 

# Connect to socket 
$sock.Connect($end) 

# Create encoded buffer 
$Enc     = [System.Text.Encoding]::ASCII 
$Message = "/network {""192.168.0.0"": ""Anon 1""}" 
$Buffer  = $Enc.GetBytes($Message) 
$Sent   = $Sock.Send($Buffer) 

$Message = "quicky hey man hows it going" 
$Buffer  = $Enc.GetBytes($Message) 
$Sent   = $Sock.Send($Buffer) 

$Message = "/add Esad" 
$Buffer  = $Enc.GetBytes($Message) 
$Sent   = $Sock.Send($Buffer)

$Message = "/add-single Mehmet 192.168.0.2" 
$Buffer  = $Enc.GetBytes($Message) 
$Sent   = $Sock.Send($Buffer) 

"{0} characters sent to: {1} " -f $Sent,$IP 
# End of Script 
