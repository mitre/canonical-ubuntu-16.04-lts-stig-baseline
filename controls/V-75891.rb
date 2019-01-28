control "V-75891" do
  title "The Ubuntu operating system must be configured to prevent unrestricted
mail relaying."
  desc  "If unrestricted mail relaying is permitted, unauthorized senders could
use this host as a mail relay for the purpose of sending spam or other
unauthorized activity."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75891"
  tag "rid": "SV-90571r2_rule"
  tag "stig_id": "UBTU-16-030620"
  tag "fix_id": "F-82521r2_fix"
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
  desc "check", "Determine if \"postfix\" is installed with the following
commands:

Note: If postfix is not installed, this is Not Applicable.

# dpkg -l | grep postfix
ii  postfix                                    3.1.0-3

Verify the Ubuntu operating system is configured to prevent unrestricted mail
relaying.

If postfix is installed, determine if it is configured to reject connections
from unknown or untrusted networks with the following command:

# postconf -n smtpd_client_restrictions

smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject

If the \"smtpd_relay_restrictions\" parameter contains any entries other than
\"permit_mynetworks\", \"permit_sasl_authenticated\" and \"reject\", is
missing, or is commented out, this is a finding."
  tag "fix": "If \"postfix\" is installed, modify the \"/etc/postfix/main.cf\"
file to restrict client connections to the local network with the following
command:

# sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks,
permit_sasl_authenticated, reject'"
end

