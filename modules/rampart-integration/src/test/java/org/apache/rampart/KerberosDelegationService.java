package org.apache.rampart;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.client.ServiceClient;
import org.apache.neethi.Policy;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;

/**
 * 
 */
public class KerberosDelegationService extends PolicyBasedResultsValidator{
    
    
    public OMElement echo(OMElement elem) throws Exception {
        final String serviceName = "KerberosOverTransportKeytab";

        ServiceClient serviceClient = RampartKerberosTest.clientHelper.createServiceClient(serviceName, null, null);

        RampartConfig rampartConfig = new RampartConfig();  
        
        KerberosConfig kerberosConfig = new KerberosConfig();
        rampartConfig.setKerberosConfig(kerberosConfig);
        kerberosConfig.setJaasContext("KerberosDelegation");
        kerberosConfig.setDelegationCredential(KerberosDelegationServiceValidator.getDelegationCredential());

        Policy policy = new Policy();
        policy.addAssertion(rampartConfig);
                
        serviceClient.getAxisService().getPolicySubject().attachPolicyComponent(policy);
        
        //Blocking invocation
        QName operation = new QName("http://rampart.apache.org", "echo");
        OMElement echoElement = getEchoElement();
        OMElement result = serviceClient.sendReceive(operation, echoElement);
        return result;
    }
    
    protected OMElement getEchoElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("echo", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    /**
     * New service method for testing negative scenario where service throws an exception
     * @param element
     * @return
     * @throws Exception
     */
    public OMElement returnError(OMElement element) throws Exception {
        throw new Exception("Testing negative scenarios with Apache Rampart. Intentional Exception");
    }    
    
}