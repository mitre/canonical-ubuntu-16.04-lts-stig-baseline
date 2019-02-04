control "V-75797" do
  title "The telnet package must not be installed."
  desc  "It is detrimental for Ubuntu operating systems to provide, or install
by default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Ubuntu operating systems are capable of providing a wide variety of
functions and services. Some of the functions and services, provided by
default, may not be necessary to support essential organizational operations
(e.g., key missions, functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software, not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.


  "
  impact 0.7
  tag "gtitle": "SRG-OS-000074-GPOS-00042"
  tag "satisfies": ["SRG-OS-000074-GPOS-00042", "SRG-OS-000095-GPOS-00049"]
  tag "gid": "V-75797"
  tag "rid": "SV-90477r2_rule"
  tag "stig_id": "UBTU-16-030000"
  tag "fix_id": "F-82427r1_fix"
  tag "cci": ["CCI-000197", "CCI-000381"]
  tag "nist": ["IA-5 (1) (c)", "CM-7 a", "Rev_4"]
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
  desc "check", "Verify that the telnet package is not installed on the Ubuntu
operating system.

Check that the telnet daemon is not installed on the Ubuntu operating system by
running the following command:

# sudo apt list telnetd

If the package is installed, this is a finding."
  desc "fix", "Remove the telnet package from the Ubuntu operating system by
running the following command:

# sudo apt-get remove telnetd"
end

