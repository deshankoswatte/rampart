/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.rampart;

import org.apache.axiom.om.OMElement;

public class Service {

	public OMElement echo(OMElement elem) {
		elem.build();
		elem.detach();
        return elem;
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
