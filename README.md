
## 🔐 **Security Groups and NACLs in AWS**

AWS provides **Security Groups** and **Network Access Control Lists (NACLs)** to control inbound and outbound traffic to resources like EC2 instances, load balancers, and more within a **Virtual Private Cloud (VPC)**.

---

### 🔸 **1. Security Groups (SG)**

**Definition:**
A **Security Group** acts as a **virtual firewall** for your EC2 instances to control **inbound and outbound traffic** at the **instance level**.

**Key Features:**

* **Stateful**: If you allow an inbound request, the response is automatically allowed.
* **Only allow rules**: You can **only add allow rules**, no deny rules.
* **Attached to ENI (Elastic Network Interface)**: Every EC2 instance has an ENI, and SGs are associated with those.
* Rules can be based on **IP addresses, protocols, ports, or other SGs**.

**Example use case:**
Allow SSH (port 22) access to an EC2 instance from your IP:

```text
Inbound rule:
Type: SSH | Protocol: TCP | Port: 22 | Source: Your IP (e.g., 203.0.113.1/32)
```

---

### 🔹 **2. Network Access Control Lists (NACLs)**

**Definition:**
A **NACL** is a **stateless firewall** that operates at the **subnet level** to control traffic **in and out of entire subnets**.

**Key Features:**

* **Stateless**: Return traffic must be explicitly allowed.
* **Supports both allow and deny rules**.
* **Evaluated in order**: Rules are evaluated in ascending order by rule number.
* Default NACL allows all traffic; custom NACLs deny all until configured.

**Example use case:**
Deny all traffic from a malicious IP across a subnet:

```text
Inbound rule:
Rule #: 100
Type: ALL traffic | Protocol: ALL | Port: ALL | Source: 203.0.113.50/32 | Action: DENY
```

---

### 🔁 **Key Differences:**

| Feature          | Security Group                         | NACL                           |
| ---------------- | -------------------------------------- | ------------------------------ |
| Level            | Instance (ENI)                         | Subnet                         |
| Stateful         | ✅ Yes                                  | ❌ No                           |
| Allow/Deny Rules | Allow only                             | Allow and Deny                 |
| Rule Evaluation  | All rules applied                      | Rules evaluated in order       |
| Default Behavior | Deny all inbound, allow outbound       | Allow all inbound and outbound |
| Use Case         | Control access to individual instances | Broad control at subnet level  |

---

### ✅ **Best Practices:**

* Use **Security Groups** for instance-level control (e.g., open port 80 on a web server).
* Use **NACLs** for **additional subnet-level security**, such as blocking IP ranges.
* Always apply **least privilege principle**: only open ports and IPs that are strictly necessary.
* Regularly audit and review SGs and NACLs for security compliance.

---

Here’s a **visual diagram** showing how **Security Groups** and **NACLs** operate in an AWS VPC, along with example configurations for both:

---

### 🧭 **Diagram: Security Group vs NACL in AWS VPC**

👇 (Visual representation showing flow and boundaries)

#### 📌 Scenario:

A public subnet hosts a web server (EC2) allowing HTTP and SSH from the internet, while a private subnet contains a database server.

```plaintext
                        ┌────────────────────────────┐
                        │         Internet           │
                        └────────────┬───────────────┘
                                     │
                          ┌──────────▼─────────┐
                          │   Internet Gateway │
                          └──────────┬─────────┘
                                     │
                             ┌───────▼────────┐
                             │  VPC (10.0.0.0/16) │
                             └───────┬────────┘
 ┌────────────────────┐              │               ┌────────────────────┐
 │  Public Subnet      │              │               │  Private Subnet     │
 │  (10.0.1.0/24)      │              │               │  (10.0.2.0/24)      │
 │                    ┌▼────────┐     │     ┌────────▼┐                   │
 │   EC2 Web Server   │  NACL    │     │     │   NACL  │    DB Server     │
 │  (10.0.1.10)        └─▲────▲──┘     │     └──▲──▲───┘  (10.0.2.10)      │
 │                    ┌▼────▼──┐      │        │  │                      │
 │                    │  SG     │<────┘        │  │                      │
 │                    └────────┘               │  │                      │
 └────────────────────┘                        └──┘                      └─
```

---

### ⚙️ **Example Configurations**

#### 🔸 1. **Security Group (Web Server SG)**

```bash
# Allow SSH from your IP
Type: SSH
Protocol: TCP
Port Range: 22
Source: 203.0.113.0/32

# Allow HTTP from anywhere
Type: HTTP
Protocol: TCP
Port Range: 80
Source: 0.0.0.0/0
```

#### 🔸 2. **Security Group (Database SG)**

```bash
# Allow MySQL traffic only from the web server SG
Type: MySQL/Aurora
Protocol: TCP
Port Range: 3306
Source: sg-0123abcd4567efgh8 (Web Server SG)
```

---

#### 🔹 3. **NACL (Public Subnet)**

| Rule # | Type      | Protocol | Port       | Source         | Allow/Deny |
| ------ | --------- | -------- | ---------- | -------------- | ---------- |
| 100    | HTTP      | TCP      | 80         | 0.0.0.0/0      | ALLOW      |
| 110    | SSH       | TCP      | 22         | 203.0.113.0/32 | ALLOW      |
| 120    | Ephemeral | TCP      | 1024-65535 | 0.0.0.0/0      | ALLOW      |
| \*     | ALL       | ALL      | ALL        | 0.0.0.0/0      | DENY       |

#### 🔹 4. **NACL (Private Subnet)**

| Rule # | Type      | Protocol | Port       | Source      | Allow/Deny |
| ------ | --------- | -------- | ---------- | ----------- | ---------- |
| 100    | MySQL     | TCP      | 3306       | 10.0.1.0/24 | ALLOW      |
| 110    | Ephemeral | TCP      | 1024-65535 | 10.0.1.0/24 | ALLOW      |
| \*     | ALL       | ALL      | ALL        | 0.0.0.0/0   | DENY       |

---

Let me know if you'd like this exported as a **PowerPoint slide**, **PDF**, or drawn as a **detailed network diagram** with AWS icons.


# Project on SecurityGroup & Nacl

## Working Security Group

**Preview**: From the previous project on Vpc we created a private and public subnet which allows us to be able to access public subnet on the internet or allows it passage to the gateway. see 👉 https://github.com/Heebrah/Vpc-Aws for reference
1. We go to subnet then to the public subnet created in the previous project
![caption](/img/1.%20checking-security-group.png)

2. I have to check my instances if i can access them after configuring them on the Vpc i created. see https://github.com/Heebrah/Market-Peak for more information on how to host a website on AWS.
 ![caption](/img/2.%20ip-address.jpg)

 3. This shows that the instance is not accessible
 ![caption](/img/3.not-open.jpg)

 ### Configuration of Security Group

 1. We go to security group under Vpc dashboard and click create **Security Groups** 
 ![caption](/img/4.security-group.jpg)

 2. Name your group, then select your created Vpc. click **Add rule** under the **inbound rules**
 ![caption](/img/5.options.jpg)

 3. enable Http and ssh access for inbound then create your security group
  ![caption](/img/6.create-group.png)

4. Next is to add the security group to the public subnet by going to **change security group** 
![caption](/img/7.change-security.jpg)

5. We then add the new security group and save 
![caption](/img/8.save-Security.jpg)

6. We can get our website now running by refreshing the webpage. 
![caption](/img/9.access-http.jpg)

## connectivity test 
1. ### Working on the Outbound

✅ We go into the **outbound** of our public to edit  the rule
![caption](/img/10.edit-outbound.jpg)

✅ Next is to delete the rule and save
 ![caption](/img/11.delete-outbond.jpg)

✅ checking my webpage am still able to access the website
 ![caption](/img/12.success-web-again.jpg)

 #### conclusion: 
 after removing outbound rule this will not affect our instance to the outside world but when instance send data to user's browser the outbound rule will prevent it.
 Security group are stateful, which means it automatically allow traffic initiated by the instance to which they are attached.

2. ### Carrying out testing on the Inbound
✅ We go into the **inbound** of our public subnet
![caption](/img/13.edit-inbound.jpg)

✅ Next we delete the rules there and save
![caption](/img/14.delete-inbound-rule.jpg)

✅ We notice our webpage will not be accessable when we reload again. This shows that the inbound is responsible for  
![caption](/img/3.not-open.jpg)

3. ### carrying out testing with outbound rule

✅ we go to edit the outbound
![caption](/img/16.edit-outbound.jpg)

✅ add the http access
![caption](/img/17.add-outbound.jpg)

✅ This still shows our website is unaccessible
![caption](/img/18.unreacheabel-site.jpg)

✅ But we can fetch data from outside using the command curl
![caption](/img/19.going-out.jpg)


## Working with NACL
The Nacl works as 
1. Go to the Network ACLs under Vpc dashboard
![caption](/img/20.Network-Acl.jpg)

2. choose your created Vpc and then click **Create network ACL**
![caption](/img/21.Nacl-creation.jpg)

3. This shows that all port are block by default on the inbound of the Nacl. so we click **Edit inbound rule**
![caption](/img/23.inbound-deny-too.jpg)

4. We will click on **Add new rule**, then we edit it to allow all traffic or specify one we want to internet source which is **0.0.0.0/0** and then save.
![caption](/img/24.edit-inbound.jpg)

5. We can see the created **Nacl** not yet associate with any subnet so we can go to **action** then click **Edit subnet association**
![caption](/img/25.subnet-associated.jpg)

6. choose your public subnet and click save
![caption](/img/26.edit-subnet.jpg)

7. success shown as we can see in the figure below which show **allow**
![caption](/img/27.success-connect.jpg)

8. Going to the **Outbound** we see it also shows block on all port. So we click **Edit Outbound rules**
![caption](/img/28.editing-outbound-nacl.jpg)

9. We will click on **Add new rule**, then we edit it to allow all traffic from internet destination which is **0.0.0.0/0** and then save.
![caption](/img/29.add-outbound.jpg)

10. So checking webpage again we can still be able to access our website
![caption](/img/30.%20success-web.jpg)

Removing the inbound rule of the Nacl won't allow us access the website again
![caption](/img/31.removing-inbound-nacl.jpg)

This will make our website not accessible again.
![caption](/img/3.not-open.jpg)



## Conclusion on the project
* **NACL allows all inbound and outbound traffic, Security Group denies all inbound and outbound traffic**:
  **Outcome**: Website access will be blocked because the Security Group denies all traffic, overriding the NACL's allowance.

* **NACL denies all inbound and outbound traffic, Security Group allows all inbound and outbound traffic**:
  **Outcome**: Website access will be blocked because the NACL denies all traffic, regardless of the Security Group's allowances.

* **NACL allows HTTP inbound traffic, outbound traffic is denied, Security Group allows inbound traffic and denies outbound traffic**:
  **Outcome**: Website access will be allowed because the Security Group allows HTTP inbound traffic, regardless of the NACL's allowances. However, if the website requires outbound traffic to function properly, it won't work due to the Security Group's denial of outbound traffic.


* NACL allows all inbound and outbound traffic, Security Group allows all inbound and outbound traffic:
  **Outcome**: Website access will be allowed, as both NACL and Security Group allow all traffic.

* NACL denies all inbound and outbound traffic, Security Group allows HTTP inbound traffic and denies outbound traffic:
  **Outcome**: Website access will be blocked because the NACL denies all traffic, regardless of the Security Group's allowances.
