asm CryptoLibrary


import StandardLibrary
import CTLlibrary

signature:
	domain Initiator subsetof Agent // Alice
	domain Receiver subsetof Agent // Bob
	domain Intruder subsetof Agent // Eve
	
	/*------------------------------------------------------------------- */
	//                    CryptoLibrary domain
	/*------------------------------------------------------------------- */
	
		enum domain StateInit = { IDLE_A | WAIT_MESS2 |  END_A } // Alice's internal state
		enum domain StateRec = { WAIT_MESS1 |  WAIT_MESS3 | END_B} // Bob's internal state
		
		enum domain Message = {MESS_NA_IDA |  MESS_NA_NB |  MESS_NB} // Message tag name
		
		enum domain Knowledge = {NA | ID_A | NB | ID_B | // Fields Knowledge (Nonce,ID Certificate)
								 PRIVKA | PRIVKB | PRIVKE | // Private Keys
								 PUBKA  | PUBKB | PUBKE | // Public Keys
								 // Knowledge contains all the subcategory (Bitstring, Nonce, ID Certificate, Symmetric Key, Asymmetric Keys, Timestmp)
								}
		domain FieldPosition subsetof Integer
		//Message example (FieldPosition indicates in which cell it is possible to find the knowledge):
		//{G,G_Y,SIGN(PRIVKS,HASH(NB,NS,G,G_Y))}PUBKS
		//1: G
		//2: G_Y
		//3: PRIVKS
		//4: NB
		//5: NS
		//6: G
		//7: G_Y	
		domain Level subsetof Integer
		//Message example (Level indicates the nesting level of a specific field):
		//{G,G_Y,SIGN(PRIVKS,HASH(NB,NS,G,G_Y))}PUBKS
		//Level 1: h = HASH(NB,NS,G,G_Y)
		//Level 2: s=SIGN(PRIVKS, h )
		//Level 3: ASYM_ENC(G,G_Y,s) 
		domain EncFieldInit subsetof Integer//where start to encrypt
		domain EncFieldEnd subsetof Integer//where finish to encrypt
		
		
	
	controlled InitiatorState: Initiator -> StateInit //The internal state of Alice
	controlled ReceiverState: Receiver -> StateRec //The internal state of Bob
	
	//The message direction and the tag of the message sent
	// must be duplicated to be verified otherwise the correct way to write it is:
	// controlled protocolMessage: Prod(Agent,Agent)-> Message
	controlled protocolMessage: Prod(Initiator,Intruder)-> Message
	controlled protocolMessage: Prod(Intruder,Initiator)-> Message
	controlled protocolMessage: Prod(Receiver,Intruder)-> Message
	controlled protocolMessage: Prod(Intruder,Receiver)-> Message
	
	//controlled messageField: Prod(FieldPosition,Message)->Knowledge
	// it is possible to use this structure for the messsage field 
	// but for the verification sake we will use the following
	controlled messageField_1_MESS_NA_IDA:Knowledge
	controlled messageField_2_MESS_NA_IDA:Knowledge
	
	controlled messageField_1_MESS_NA_NB:Knowledge
	controlled messageField_2_MESS_NA_NB:Knowledge
	
	controlled messageField_1_MESS_NB:Knowledge
	
	// We associate to a certain level of nesting of a specific message from a init field to end field a public encryption key
	controlled asymEnc: Prod(Message,Level,EncFieldInit,EncFieldEnd)-> Knowledge // Knowledge is a Public key
	// The decription checks if a principal knows the decryption key
	static asymDec: Prod(Message,Level,EncFieldInit,EncFieldEnd,Intruder)-> Boolean
	static asymDec: Prod(Message,Level,EncFieldInit,EncFieldEnd,Receiver)-> Boolean
	static asymDec: Prod(Message,Level,EncFieldInit,EncFieldEnd,Initiator)-> Boolean
	
	// We associate to a certain level of nesteni of a specific message from a init field to end field a symmetric encryption key
	controlled symEnc: Prod(Message,Level,EncFieldInit,EncFieldEnd)-> Knowledge //Knowledge is a symmetric key
	// The decription checks if a principal knows the decryption key
	static symDec: Prod(Message,Level,EncFieldInit,EncFieldEnd,Intruder)-> Boolean
	static symDec: Prod(Message,Level,EncFieldInit,EncFieldEnd,Receiver)-> Boolean
	static symDec: Prod(Message,Level,EncFieldInit,EncFieldEnd,Initiator)-> Boolean
	
	//The first Knowledge must be AsymPubKey the second AsymPrivKey and the result must be SymKey
	static diffieHellman:Prod(Knowledge,Knowledge)->Knowledge
	
	
	static alice: Initiator
	static bob: Receiver
	static eve: Intruder
	
	definitions:
		domain Level = {1}
		domain FieldPosition = {1:2}
