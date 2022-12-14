# Security Token Service

## Introduction

This is a Security Token Service (STS) based on the WS-Trust Standard and compactible for the BiPRO Norm 410 as used in the Germany Insurance Industry.

The STS issues *JWT tokens* that can be verified with various common products for Single-Sign On, Web Application Firewalls or Cloud services.
 
## Usage

Start the *Spring Boot* application and check out the endpoints

```
GET /ws/oauth/token for a simple OAuth2 Client authentication flow and
POST /ws/sts/UserPasswordLogin for a SOAP WS-Security with UsernamePasswort header against a LDAP server
POST /ws/sts/VDGTicketLogin for a SOAP WS-Security with a BinaryTicket (VDG Ticket), needs certain configuration of certificates
POST /ws/sts/SpringAuthentication for a SOAP WS-Security when Spring already performed an authentication (via proxy or SSO)
POST /ws/sts/ValidateToken for a SOAP WS-Security ticket validation
POST /ws/sts/CancelToken for a SOAP WS-Security ticket cancellation
```

Sample requests can be found in the _src/test/resorces/examples_ folder.

## Security

This application has been hardened for security reasons by several measures based on the OWASP Top 10 and others:

| Attack vector | Countermeasure | See |
| ------------- | -------------- | --- |
| Transmission of sensitive data (passwords) | HTTPS activated and enforced by default | application.properties |
| Vulnerable and Outdated Components | This application is based on *Spring Boot* and can therefore be updated easily to the latest versions | pom.xml |
| Cryptographic Failures | Use standard JDK and Spring Components | pom.xml |
| XML External Entities (XXE) attack | Disabled per default | Testcase |

I recommend to run the Spring Boot application with *Java Security Manager* in order to control all access to resources (files, network).

## Settings

See *application.properties* for a description of all settings. You will need a **LDAP server** for authentication and user storage as well as a **database** (could use H2 in-memory, but that's not recommended) to keep track of all issued tokens.

## Database

Please set up and configure a database for the tokens using JDBC:

```
CREATE TABLE TOKENS (
  ID VARCHAR2(36) PRIMARY KEY, 
  TOKEN VARCHAR2(512) NOT NULL,
  USERID VARCHAR2(30) NOT NULL,
  ISSUEDAT TIMESTAMP NOT NULL,
  EXPIRESAT TIMESTAMP NOT NULL,
);
```
## Sample requests

Please find some sample requests in *src/test/resources/examples*.
	
## License

This application is published under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Contact

Please contact me for any questions via email: [erichambuch@googlemail.com](mailto:erichambuch@googlemail.com) or via GitHub.

Copyright 2022 Eric Hambuch