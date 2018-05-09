// ID: %{checksum} - Do not alter this line
import org.apache.commons.net.util.SubnetUtils
def CLI_READY = ~/.*> /  // pattern to recognise a device ready prompt

attributes {
    specificationVersion =      "%{plugin.specification.version}"
    implementationVersion =     "%{plugin.implementation.version}"

    // Some basic attributes like name, version etc
    pluginName = "Fujitsu IpCom EX2-3000"
    platform = "IpCom_EX2_3000"
    aliases = [ "IpCom_EX2_3000" ]
    pluginVersion = "1.0"
    // Indicates we will use CliParser to parse the config. This can be one of cli, json, xml, custom.
    parserType = ParserType.cli

    // validationSettings are used to auto detect which plugin to use during file import. Below, we are specifying the
    // pattern to find in the first maxLines
    validationSettings = [
       patterns : [ /hostname \S*.*/ ],
       comment : "!",
       maxLines : 4,
       validationXml : false
    ]

    // Similar to validationSettings, these settings are used to auto detect live device - what command to run and
    // what pattern to look for
    commsAutoDetectSettings = [
       waitFor : CLI_READY,
       command : 'display version',
       expect: ~/^SC Software.*/,
       linesToRead: 2
    ]
}


comms { // This section has code to communicate over various protocols to fetch details from the device
    using ('telnet/ssh') { // Blocks for various comms protocols. Can be telnet/ssh http/https and custom

        login {
            log.debug("Login")
            if (protocol == 'telnet') {
                log.debug 'telnet true'
                _useStandardLogin(CLI_READY, ~/(?s).*login: /, ~/(?s)Password: /)
            } else if (protocol == 'ssh') {
                log.debug 'ssh true'
                _useStandardLogin(CLI_READY, ~/(?s).*login: /, ~/(?s)Password: /)
            } else {
                log.debug 'not supported'
            }

            sendAndReadUntil 'terminal pager disable', CLI_READY
        }

        getConfig { // Section to get the config

           def cfg = sendAndReadUntil 'show running-config', CLI_READY
            log.debug("Got config $cfg")

            return cfg
        }

        getL2 { // (Optional) Section to get L2 information if supported for the device
        
        	// interface
        	def intf = sendAndReadUntil 'show interface', CLI_READY
            log.debug("Got interface $intf")

            return intf
        }

        getDynamicRouting { // (Optional) Section to get dynamic routing information if supported for the device
        }
    }
}


parser {
    patterns = [
        ip : "(?<ip>(?:\\d{1,3}\\.){3}\\d{1,3})",
        ipRange : "(?:(?<address>[\\d\\.]+)(?: (?<wildcard>[\\d\\.]+))?|any)",
        getLine : "(?<line>.*)",
        getL2 : "(?<line>.*(?:MTU\\:).*)",
    ]
    grammar = """
hostname %{name}

// Interfaces
interface %{name}
  description ?{description}
  ip address (?:&{ip:address} &{ip:mask}|auto|%{ipAndMask} ?{option})
  vlanLink:: vlan-link %{namePort} %{option}
  speed %{speed}
  duplex %{duplex}
  negotiation:: auto-negotiation %{status}
  ipRouting:: ip-routing %{ipRouting}
  ipv6Address:: ipv6 address %{ipv6Address}
  ipv6Routing:: ipv6-routing
  ipv6Redirects:: ipv6-redirects
  exit

// Ip route
ipRoute:: ip route %{routeAdress} %{routeMark}

// user-role
userRole::user-role %{name}
  description %{description}
  displayName:: display-name %{display}

// user
user %{name}
  password:: secret-password %{strip}
  authentication %{auth}
  
// L2
// interface
interfaceL2:: &{getL2:name}
  tpye:: Type\\: &{getLine:typeName}
  description:: Description\\: ?{description}
  macAddress:: MAC address\\: %{macAddress}
"""
}

isManagement = { String intfName ->
    boolean result = false
    if (intfName ==~ /(?i)^mnt.*$/){
        result = true
    }
    return result
}

getIpAndMask = {ipAndMask ->
    rtIpDetails = [:]

    SubnetUtils subnetUtils = new SubnetUtils(ipAndMask)
    SubnetUtils.SubnetInfo subnetInfo = subnetUtils.getInfo()

    mask = subnetInfo.getNetmask()
    ipAddress = subnetInfo.getAddress()
    rtIpDetails << [address: ipAddress, netmask: mask]

    return rtIpDetails
}

rsxml {
    systems {
        if (!parsedConfig.hostname)
            _failImport("Invalid config", null)
        system(name: parsedConfig.hostname.first().name, primaryCapability: 'ROUTER', isRouting: true, deviceType: 'IPCOMEX2') {

            // Set version if it is present in the AST, or to "Unknown_Version".
            // We do it succinctly using
            //   safe navigation operator (http://mrhaki.blogspot.in/2009/08/groovy-goodness-safe-navigation-to.html) and
            //   elvis operator (http://mrhaki.blogspot.in/2009/08/groovy-goodness-elvis-operator.html)
            def version = parsedConfig.version?.first()?.version ?: "IN Software v01"

            // create the OS node. Use the version we just parsed
            OS(name: 'Mac OS', vendor: 'Redseal', versionString: version)

            log.debug(parsedConfig.interfaceL2?:"null-l2")
            boolean readFormCommand = parsedConfig.interfaceL2?true:false
            def listInterface = parsedConfig.interfaceL2?:parsedConfig.interface

            // We only need the active interfaces, so find them
            def activeInterfaces = listInterface.findAll {
                // active interface is one which is not shut and has an ip
                // case show interface not check
                def active = (!it.shut && it.ip || it.nameLine)
                if (!active) // In this sample, we will add warnings for non-active interfaces.
                    _addInconsistencyParserWarning("Skipping ${it.name} since it is not configured", it.line)
                return active
            }

            // start content of config file
            def rawConfigs = ['config':rawConfig]
            _createConfigNode(rawConfigs)
            // end content of config
           
            // group name
            interfaceNames = []

            if (!readFormCommand) {
                log.debug("read from config file file ---------------------")
                addNetworkPortsFromConfig(activeInterfaces)
                } else {
                    log.debug("read via command ---------------------")
                    log.debug(activeInterfaces)
                    // start network ports
                    rsXmlBuilder.networkPorts {
                        activeInterfaces.each { intf ->    // Add each of the active interfaces.
                        def intfMap = []
                        String beforeNameLine = intf.nameLine?:"UnKnown"
                        String[] nameArray = beforeNameLine.replaceAll("\\s+", " ").split(" ")
                        log.debug( "AAAAA" + nameArray?:"")

                        //log.debug(intf)
                        def intfName = nameArray[0]
                        interfaceNames << intfName
                        type = intf.type
                            if (!type) {
                                if (intfName ==~ /(?i)^.*(mnt|lan|bnd|channel|vlan|pass|ppp).*$/)
                                    type = 'ETHERNET'
                                else
                                    type = 'UNKNOWN'
                            }
                            def networkAddress = intf.macAddress?.macAddress?.first()?:null
                            intfMap = [name: intfName, type: type, networkAddress: networkAddress]
                            /*def allIpDetails = [] // Array to store all the configured IP details.
                            intf.ip.each { ip ->
                                def ipDetails = []
                                def secDetails = []
                                if(ip.address != null) {
                                    ipDetails = [address: ip.address, netmask: ip.mask] // Extract the address and mask
                                } else {
                                    ipMask = ip.ipAndMask
                                    if (ipMask != null){
                                        ipDetails = getIpAndMask(ipMask)
                                    }
                                }
                                if (isManagement(intfName)) {
                                    ipDetails << [management: "true"]
                                }
                                allIpDetails << ipDetails
                            }*/

                            /*def allNegoDetails = []
                            intf.negotiation.each { nego ->
                                def dataNego = nego.status?:"UnKnown"
                                allNegoDetails = [negotiation: dataNego]
                            }*/
                            /*String show = allIpDetails.get(0).address
                            if (show.size() > 2){
                                intfMap << [ip: allIpDetails]
                            }*/
                            def des = intf.description?.first()?.description?:null
                            intfMap << [description: des]

                            /*String ipv6AddressAndMask = intf.ipv6Address?.first()?.ipv6Address?:"None"
                            if (!ipv6AddressAndMask.equals("None")) {
                                def ipv6Details = [aliasName: intf.name + " ipv6"]
                                String[] splits = ipv6AddressAndMask.split("/")
                                def ipv6Address
                                def ipv6Mask
                                if (splits.size() == 2) {
                                    ipv6Address = splits[0]
                                    ipv6Mask = splits[1]
                                }
                                ipv6Details << [address: ipv6Address, maskLength: ipv6Mask, type: "STATIC"]
                                intfMap << [ipv6: [ipv6Details]]
                            }*/

                            log.debug(intfMap)
                            _mapToNetworkPort(intfMap)
                            

                        }
                    }
                    // end network ports
                }
            

            ///////////////
            // IP GROUPS //
            ///////////////

            ipGroups {
                group(ref: "Any"){
                    interfaceNames.each { intfName ->
                        aliasName(intfName)
                    }
                }
            }

        }
    }
}


def addNetworkPortsFromConfig(activeInterfaces) {
    // start network ports
    rsXmlBuilder.networkPorts {
        activeInterfaces.each { intf ->    // Add each of the active interfaces.
        def intfMap = []

        //log.debug(intf)
        def intfName = intf.name?:"UnKnown"
        interfaceNames << intfName
        type = intf.type
            if (!type) {
                if (intf.name ==~ /(?i)^.*(mnt|lan|bnd|channel|vlan|pass|ppp).*$/)
                    type = 'ETHERNET'
                else
                    type = 'UNKNOWN'
            }

            intfMap = [name: intf.name, type: type]
            def allIpDetails = [] // Array to store all the configured IP details.
            intf.ip.each { ip ->
                def ipDetails = []
                def secDetails = []
                if(ip.address != null) {
                    ipDetails = [address: ip.address, netmask: ip.mask] // Extract the address and mask
                } else {
                    ipMask = ip.ipAndMask
                    if (ipMask != null){
                        ipDetails = getIpAndMask(ipMask)
                    }
                }
                if (isManagement(intfName)) {
                    ipDetails << [management: "true"]
                }
                allIpDetails << ipDetails
            }

            def allNegoDetails = []
            intf.negotiation.each { nego ->
                def dataNego = nego.status?:"UnKnown"
                allNegoDetails = [negotiation: dataNego]
            }
            String show = allIpDetails.get(0).address
            if (show.size() > 2){
                intfMap << [ip: allIpDetails]
            }
            def des = intf.description?.first()?.description?:"None"
            intfMap << [description: des]

            String ipv6AddressAndMask = intf.ipv6Address?.first()?.ipv6Address?:"None"
            if (!ipv6AddressAndMask.equals("None")) {
                def ipv6Details = [aliasName: intf.name + " ipv6"]
                String[] splits = ipv6AddressAndMask.split("/")
                def ipv6Address
                def ipv6Mask
                if (splits.size() == 2) {
                    ipv6Address = splits[0]
                    ipv6Mask = splits[1]
                }
                ipv6Details << [address: ipv6Address, maskLength: ipv6Mask, type: "STATIC"]
                intfMap << [ipv6: [ipv6Details]]
            }

            log.debug(intfMap)
            _mapToNetworkPort(intfMap)
            

        }
    }
    // end network ports
}