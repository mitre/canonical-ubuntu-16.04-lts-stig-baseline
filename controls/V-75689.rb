control "V-75689" do
  title "The audit system must be configured to audit the execution of
privileged functions and prevent all software from executing at higher
privilege levels than users executing the software."
  desc  "Misuse of privileged functions, either intentionally or
unintentionally by authorized users, or by unauthorized external entities that
have compromised information system accounts, is a serious and ongoing concern
and can have significant adverse impacts on organizations. Auditing the use of
privileged functions is one way to detect such misuse and identify the risk
from insider threats and the advanced persistent threat.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000326-GPOS-00126"
  tag "satisfies": ["SRG-OS-000326-GPOS-00126", "SRG-OS-000327-GPOS-00127"]
  tag "gid": "V-75689"
  tag "rid": "SV-90369r2_rule"
  tag "stig_id": "UBTU-16-020350"
  tag "fix_id": "F-82317r2_fix"
  tag "cci": ["CCI-002233", "CCI-002234"]
  tag "nist": ["AC-6 (8)", "AC-6 (9)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system audits the execution of
privilege functions.

Verify if the Ubuntu operating system is configured to audit the execution of
the \"execve\" system call, by running the following command:

# sudo grep execve /etc/audit/audit.rules

-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv

If the command does not return both lines, or the line is commented out, this
is a finding. "
  tag "fix": "Configure the Ubuntu operating system to audit the execution of
the \"execve\" system call.

Add or update the following file system rules to \"/etc/audit/audit.rules\":

-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv

The audit daemon must be restarted for the changes to take effect. To restart
the audit daemon, run the following command:

# sudo systemctl restart auditd.service"
end

