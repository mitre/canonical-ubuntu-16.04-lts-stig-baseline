control "V-75803" do
  title "An application firewall must be installed."
  desc  "Uncomplicated Firewall provides a easy and effective way to
block/limit remote access to the system, via ports, services and protocols.

    Remote access services, such as those providing remote access to network
devices and information systems, which lack automated control capabilities,
increase risk and make remote user access management difficult at best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Ubuntu operating system functionality (e.g., RDP) must be capable of taking
enforcement action if the audit reveals unauthorized activity. Automated
control of remote access sessions allows organizations to ensure ongoing
compliance with remote access policies by enforcing connection rules of remote
access applications on a variety of information system components (e.g.,
servers, workstations, notebook computers, smartphones, and tablets).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000297-GPOS-00115"
  tag "gid": "V-75803"
  tag "rid": "SV-90483r2_rule"
  tag "stig_id": "UBTU-16-030030"
  tag "fix_id": "F-82433r1_fix"
  tag "cci": ["CCI-002314"]
  tag "nist": ["AC-17 (1)", "Rev_4"]
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
  tag "check": "Verify that the Uncomplicated Firewall is installed.

Check that the Uncomplicated Firewall is installed with the following command:

# sudo apt list ufw

ii  ufw         0.35-0Ubuntu2 [installed]

If the \"ufw\" package is not installed, ask the System Administrator if
another application firewall is installed. If no application firewall is
installed this is a finding."
  tag "fix": "Install Uncomplicated Firewall with the following command:

# sudo apt-get install ufw"
end

