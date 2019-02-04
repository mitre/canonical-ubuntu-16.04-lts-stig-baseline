control "V-75807" do
  title "An application firewall must employ a deny-all, allow-by-exception
policy for allowing connections to other systems."
  desc  "Failure to restrict network connectivity only to authorized systems
permits inbound connections from malicious systems. It also permits outbound
connections that may facilitate exfiltration of DoD data.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000297-GPOS-00115"
  tag "satisfies": ["SRG-OS-000297-GPOS-00115", "SRG-OS-000480-GPOS-00231"]
  tag "gid": "V-75807"
  tag "rid": "SV-90487r2_rule"
  tag "stig_id": "UBTU-16-030050"
  tag "fix_id": "F-82437r1_fix"
  tag "cci": ["CCI-000366", "CCI-002080", "CCI-002314"]
  tag "nist": ["CM-6 b", "CA-3 (5)", "AC-17 (1)", "Rev_4"]
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
  desc "check", "Verify the Uncomplicated Firewall is configured to employ a
deny-all, allow-by-exception policy for allowing connections to other systems.

Check the Uncomplicated Firewall configuration with the following command:
# sudo ufw status
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22                         LIMIT IN    Anywhere

If any services, ports, or applications are \"allowed\" and are not documented
with the organization, this is a finding."
  desc "fix", "Configure the Uncomplicated Firewall to employ a deny-all,
allow-by-exception policy for allowing connections to other systems.

Remove any service that is not needed or documented by the organization with
the following command (replace [NUMBER] with the rule number):

# sudo ufw delete [NUMBER]

Another option would be to set the Uncomplicated Firewall back to default with
the following commands:

# sudo ufw default deny incoming
# sudo ufw default allow outgoing

Note: UFW’s defaults are to deny all incoming connections and allow all
outgoing connections."
end

