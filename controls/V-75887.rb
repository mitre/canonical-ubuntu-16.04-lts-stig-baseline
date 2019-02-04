control "V-75887" do
  title "The Ubuntu operating system must not be performing packet forwarding
unless the system is a router."
  desc  "Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75887"
  tag "rid": "SV-90567r2_rule"
  tag "stig_id": "UBTU-16-030600"
  tag "fix_id": "F-82517r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify the Ubuntu operating system is not performing packet
forwarding, unless the system is a router.

Check to see if IP forwarding is enabled using the following command:

# /sbin/sysctl -a | grep  net.ipv4.ip_forward
net.ipv4.ip_forward=0

If IP forwarding value is \"1\" and is not documented with the Information
System Security Officer (ISSO) as an operational requirement , this is a
finding."
  desc "fix", "Configure the Ubuntu operating system to not allow packet
forwarding, unless the system is a router with the following command:

# sudo sysctl -w net.ipv4.ip_forward=0

If \"0\" is not the system's default value then add or update the following
line in \"/etc/sysctl.conf\" or in the appropriate file under \"/etc/sysctl.d\":

net.ipv4.ip_forward=0"
end

