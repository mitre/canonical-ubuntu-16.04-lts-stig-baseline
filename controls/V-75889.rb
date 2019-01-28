control "V-75889" do
  title "Network interfaces must not be in promiscuous mode."
  desc  "Network interfaces in promiscuous mode allow for the capture of all
network traffic visible to the system. If unauthorized individuals can access
these applications, it may allow then to collect information such as logon IDs,
passwords, and key exchanges between systems.

    If the system is being used to perform a network troubleshooting function,
the use of these tools must be documented with the Information System Security
Officer (ISSO) and restricted to only authorized personnel.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75889"
  tag "rid": "SV-90569r2_rule"
  tag "stig_id": "UBTU-16-030610"
  tag "fix_id": "F-82519r2_fix"
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
  desc "check", "Verify network interfaces are not in promiscuous mode unless
approved by the Information System Security Officer (ISSO) and documented.

Check for the status with the following command:

# ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use
has not been approved by the ISSO and documented, this is a finding."
  tag "fix": "Configure network interfaces to turn off promiscuous mode unless
approved by the Information System Security Officer (ISSO) and documented.

Set the promiscuous mode of an interface to \"off\" with the following command:

# sudo ip link set dev <devicename> promisc off"
end

