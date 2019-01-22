control "V-75823" do
  title "The Ubuntu operating system must enforce SSHv2 for network access to
all accounts."
  desc  "A replay attack may enable an unauthorized user to gain access to the
Ubuntu operating system. Authentication sessions between the authenticator and
the Ubuntu operating system validating the user credentials must not be
vulnerable to a replay attack.

    An authentication process resists replay attacks if it is impractical to
achieve a successful authentication by recording and replaying a previous
authentication message.

    A privileged account is any information system account with authorizations
of a privileged user.

    Techniques used to address this include protocols using nonces (e.g.,
numbers generated for a specific one-time use) or challenges (e.g., TLS,
WS_Security). Additional techniques include time-synchronous or
challenge-response one-time authenticators.


  "
  impact 0.7
  tag "gtitle": "SRG-OS-000112-GPOS-00057"
  tag "satisfies": ["SRG-OS-000112-GPOS-00057", "SRG-OS-000113-GPOS-00058"]
  tag "gid": "V-75823"
  tag "rid": "SV-90503r1_rule"
  tag "stig_id": "UBTU-16-030200"
  tag "fix_id": "F-82453r1_fix"
  tag "cci": ["CCI-001941", "CCI-001942"]
  tag "nist": ["IA-2 (8)", "IA-2 (9)", "Rev_4"]
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
  tag "check": "Verify that the Ubuntu operating system enforces SSH protocol 2
for network access.

Check the protocol versions that SSH allows with the following command:

#grep -i protocol /etc/ssh/sshd_config

Protocol 2

If the returned line allows for use of protocol \"1\", is commented out, or the
line is missing, this is a finding."
  tag "fix": "Configure the Ubuntu operating system to enforce SSHv2 for
network access to all accounts.

Add or update the following line in the \"/etc/ssh/sshd_config\" file:

Protocol 2

Restart the ssh service.

# systemctl restart sshd.service"
end

