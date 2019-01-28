control "V-75809" do
  title "The Ubuntu operating system must be configured to prohibit or restrict
the use of functions, ports, protocols, and/or services, as defined in the
Ports, Protocols, and Services Management (PPSM) Category Assignments List
(CAL) and vulnerability assessments."
  desc  "In order to prevent unauthorized connection of devices, unauthorized
transfer of information, or unauthorized tunneling (i.e., embedding of data
types within data types), organizations must disable or restrict unused or
unnecessary physical and logical ports/protocols on information systems.

    Ubuntu operating systems are capable of providing a wide variety of
functions and services. Some of the functions and services provided by default
may not be necessary to support essential organizational operations.
Additionally, it is sometimes convenient to provide multiple services from a
single component (e.g., VPN and IPS); however, doing so increases risk over
limiting the services provided by any one component.

    To support the requirements and principles of least functionality, the
Ubuntu operating system must support the organizational requirements, providing
only essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official
business or to address authorized quality of life issues.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-75809"
  tag "rid": "SV-90489r2_rule"
  tag "stig_id": "UBTU-16-030060"
  tag "fix_id": "F-82439r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  tag "fix": "Add/Modify the Ubuntu operating system's firewall settings and/or
running services to comply with the Ports, Protocols, and Services Management
(PPSM) Category Assignments List (CAL)."
end

