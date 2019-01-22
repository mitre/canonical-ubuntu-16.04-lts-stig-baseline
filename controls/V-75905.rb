control "V-75905" do
  title "The Ubuntu operating system must accept Personal Identity Verification
(PIV) credentials."
  desc  "The use of PIV credentials facilitates standardization and reduces the
risk of unauthorized access.

    DoD has mandated the use of the CAC to support identity management and
personal authentication for systems covered under Homeland Security
Presidential Directive (HSPD) 12, as well as making the CAC a primary component
of layered protection for national security systems.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000376-GPOS-00161"
  tag "gid": "V-75905"
  tag "rid": "SV-90585r1_rule"
  tag "stig_id": "UBTU-16-030810"
  tag "fix_id": "F-82535r1_fix"
  tag "cci": ["CCI-001953"]
  tag "nist": ["IA-2 (12)", "Rev_4"]
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
  tag "check": "Verify the Ubuntu operating system accepts Personal Identity
Verification (PIV) credentials.

Check that the \"opensc-pcks11\" package is installed on the system with the
following command:

# dpkg -l | grep opensc-pkcs11

ii opensc-pkcs11:amd64 0.15.0-1Ubuntu1 amd64 Smart card utilities with support
for PKCS#15 compatible cards

If the \"opensc-pcks11\" package is not installed, this is a finding."
  tag "fix": "Configure the Ubuntu operating system to accept Personal Identity
Verification (PIV) credentials.

Install the \"opensc-pkcs11\" package using the following command:

# sudo apt-get install opensc-pkcs11"
end

