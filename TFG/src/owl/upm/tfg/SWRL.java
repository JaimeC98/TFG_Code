package owl.upm.tfg;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLAxiom;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.semanticweb.owlapi.util.DefaultPrefixManager;
import org.semanticweb.owlapi.util.InferredAxiomGenerator;
import org.semanticweb.owlapi.util.InferredOntologyGenerator;
import org.semanticweb.owlapi.util.InferredSubClassAxiomGenerator;
import org.swrlapi.core.SWRLRuleEngine;
import org.swrlapi.exceptions.SWRLBuiltInException;
import org.swrlapi.factory.SWRLAPIFactory;
import org.swrlapi.parser.SWRLParseException;
import com.clarkparsia.pellet.owlapiv3.PelletReasoner;
import com.clarkparsia.pellet.owlapiv3.PelletReasonerFactory;


public class SWRL {
	
	static final OWLOntologyManager man = OWLManager.createOWLOntologyManager();
	static final OWLDataFactory df = man.getOWLDataFactory();

	@SuppressWarnings("resource")
	private static File copyFileOWL(File sourceFile, File destFile) throws IOException {
		if (destFile.exists()) {
			destFile.delete();
		}
		destFile.createNewFile();

		FileChannel source = null;
		FileChannel destination = null;
		try {
			source = new RandomAccessFile(sourceFile, "rw").getChannel();
			destination = new RandomAccessFile(destFile, "rw").getChannel();

			long position = 0;
			long count = source.size();

			source.transferTo(position, count, destination);
		} finally {
			if (source != null) {
				source.close();
			}
			if (destination != null) {
				destination.close();
			}
		}
		return destFile;
	}

	private static void createIndiv(String b, String name, OWLClass c, int n, OWLOntology o, OWLOntologyManager man, OWLDataFactory df) throws OWLOntologyStorageException {

		for (int i = 1; i<=n; i++){
			OWLIndividual anomaly_instance = df.getOWLNamedIndividual(IRI.create(name + "_" + String.valueOf(i)));
			OWLClassAssertionAxiom axioma0 = df.getOWLClassAssertionAxiom(c, anomaly_instance);
			man.addAxiom(o, axioma0);
		}
		man.saveOntology(o);

	}

	private static void inferSWRLEngine(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {


		SWRLRuleEngine swrlRuleEngine = SWRLAPIFactory.createSWRLRuleEngine(o);
		swrlRuleEngine.infer();
		man.saveOntology(o);
		swrlRuleEngine = null;
	}

	private static void loadReasoner(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, OWLReasoner reasoner) throws OWLOntologyStorageException {


		System.out.println("Using reasoner: "+ reasoner.getReasonerName());
		System.out.println("The ontology consistency is "+reasoner.isConsistent());
		reasoner.precomputeInferences();
		System.out.println("Loading infered axioms to the ontology...");
		loadInferedAxiomsByReasoner(o, man, dataFactory, reasoner);


	}

	private static void loadInferedAxiomsByReasoner(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, OWLReasoner reasoner) throws OWLOntologyStorageException {

		//What was inferred is written to the ontology
		List<InferredAxiomGenerator<? extends OWLAxiom>> gens = new ArrayList<InferredAxiomGenerator<? extends OWLAxiom>>();
		gens.add(new InferredSubClassAxiomGenerator());

		//Create the inferred ontology generator
		InferredOntologyGenerator iog = new InferredOntologyGenerator(reasoner, gens);
		iog.fillOntology(dataFactory, o);

		man.saveOntology(o);

	}

	private static void inf_anom(OWLOntology o, String anomalies_type, String amenazas_type, String prob, String impact, OWLOntologyManager man) throws OWLOntologyStorageException, SWRLParseException, SWRLBuiltInException {
		SWRLRuleEngine re = SWRLAPIFactory.createSWRLRuleEngine(o);

		String swrl_query = "tfg:" + anomalies_type + "(?a) ^ swrlx:makeOWLThing(?x, ?a) -> tfg:probability(?x, \"" + prob + "\"^^xsd:float) ^ " + "tfg:" + amenazas_type + "(?x) ^ tfg:type(?x, \"" + amenazas_type + "\") ^ tfg:impact(?x, \"" + impact + "\"^^xsd:float) ^ tfg:isGeneratedBy(?x, ?a) ^ tfg:generates(?a, ?x)";
		re.createSWRLRule("Anomalies " + anomalies_type, swrl_query);
		
		System.out.println("Creadas reglas " + anomalies_type + " - " + amenazas_type);
		
		man.saveOntology(o);

	}
	
	private static void inf_risks(OWLOntology o, String[] amenazas, OWLOntologyManager man) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		SWRLRuleEngine re = SWRLAPIFactory.createSWRLRuleEngine(o);
		
		for (String amenaza:amenazas) {
			String swrl_query = "tfg:" + amenaza + "(?a) ^ tfg:" + amenaza + "Risk (?r) -> tfg:isGeneratedBy(?r, ?a) ^ tfg:generates(?a, ?r)";
			re.createSWRLRule("Amenaza " + amenaza, swrl_query);
			
			System.out.println("Creadas reglas " + amenaza + " - Risk");
			
		}
		
		man.saveOntology(o);
		
	}
	
	private static void asset_vuln(OWLOntology o, PrefixManager b) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
			
		// Crear la vulnerabilidad
		OWLIndividual vuln = df.getOWLNamedIndividual(IRI.create("V1"));
		OWLClassAssertionAxiom axioma0 = df.getOWLClassAssertionAxiom(df.getOWLClass(":Vulnerability", b), vuln);
		man.addAxiom(o, axioma0);
		
		SWRLRuleEngine re = SWRLAPIFactory.createSWRLRuleEngine(o);
		
		// Regla que associa el router con la vulnerabilidad
		String swrl_query = "tfg:Hardware (?hw) ^ tfg:type(?hw, \"R\"^^xsd:string) ^ tfg:Vulnerability (?v) -> tfg:has_vulnerability(?hw, ?v)";
		re.createSWRLRule("Asset-Vuln", swrl_query);
		System.out.println("Creada regla Asset(R) - Vulnerability");
		
		//Regla que asocia (vuln+asset) con amenaza
		swrl_query = "tfg:Hardware (?hw) ^ tfg:type(?hw, \"R\") ^ tfg:Vulnerability (?v) ^ tfg:has_vulnerability(?hw, ?v) ^ swrlx:makeOWLThing(?x,?hw) -> tfg:NetworkOutage(?x) ^ tfg:isExposedTo(?hw,?x) ^ tfg:probability(?x, \"8.0\"^^xsd:float) ^ tfg:impact(?x, \"9.0\"^^xsd:float)";
		re.createSWRLRule("Vulneability-Asset-Threat", swrl_query);
		System.out.println("Creada regla Threat - Asset(R) - Vulnerability");
		
		man.saveOntology(o);
		
	}
	
    static long tmp[] = new long[13];
    
	private static void base_test(OWLOntology o, String base, OWLOntologyManager man, OWLDataFactory df, int ind, int array) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {

	//	Tres individuos de anomalia para: Firewall_Anomaly, Bluetooth_Sensor_Anomaly y WiFi_Sensor_Anomaly; 
		String [] anomalies_type = {"Firewall_Anomaly", "Bluetooth_Sensor_Anomaly", "WiFi_Sensor_Anomaly"};
		
	// Anomalias relacionadas mediante generates/isGeneratedBy con las amenazas: DeliberatedUnauthorizedAccess, DenialOfService y ConfigurationError
		@SuppressWarnings("deprecation")
		PrefixManager b = new DefaultPrefixManager(base + "#");
		for (int i=0; i<anomalies_type.length; i++) {

			String s_anom = base + "#"+ anomalies_type[i];
			OWLClass anomaly = df.getOWLClass(":"+anomalies_type[i], b);
			createIndiv(base, s_anom, anomaly, ind, o, man, df);
			System.out.println("Individuos creados de la clase " + anomalies_type[i]);
		}
		long tInicio = System.currentTimeMillis();
		OWLReasonerFactory reasonerFactory = PelletReasonerFactory.getInstance();
		PelletReasoner reasoner =  (PelletReasoner) reasonerFactory.createReasoner(o);
		reasoner.precomputeInferences();
		loadReasoner(o, man, df, reasoner);
		
		String [] amenazas_types = {"DeliberatedUnauthorizedAccess", "DenialOfService", "ConfigurationError"};
		String [] probabilidades = {"4.0", "8.0", "7.0"};
		String [] impactos = {"6.0", "3.0", "7.0"};
		
		for(int i=0; i<anomalies_type.length; i++) {
			inf_anom(o, anomalies_type[i], amenazas_types[i], probabilidades[i], impactos[i], man);
		}
	// Las amenazas se relacionan de nuevo con el individuo de riesgo correspondiente para cada clase (añadiendo el sufijo Risk_Risk al nombre de la clase) mediantes generates/isGeneratedBy.
		inf_risks(o, amenazas_types, man);
/*
	// El asset escogido (Router) tiene una vulnerabilidad(V1) relacionada mediante la propiedad has_vulnerability y está expuesto a una amenaza de la clase NetworkOutage medinate isExposedTo; 
		// la amenaza a su vez genera el riesgo correspondiente mediante la propiedad generates/isGeneratedBy.
		String [] amenazas = {"NetworkOutage"};
		asset_vuln(o, b);
		inf_risks(o, amenazas, man);
*/
		inferSWRLEngine(o, man, df);
		man.saveOntology(o);
		long tFin = System.currentTimeMillis();
        tmp[array] = tFin-tInicio;
	}
    //Prueba para comprobar cuantos individuos puede crear SWRL
	public static void main(String [] args) throws IOException, OWLOntologyCreationException, OWLOntologyStorageException, SWRLParseException, SWRLBuiltInException {
		int individuos [] = { 5, 10, 30, 50, 70, 90, 100, 150, 200, 250, 500, 750, 1000 };
		// TODO - rutas al fichero origen y destino
					File f_orig = new File("C:\\Users\\gonca\\Desktop\\Jaime Castro\\Cosas TFG\\SWRL\\TFG_base.owl");
					File f_save = new File("C:\\Users\\gonca\\Desktop\\Jaime Castro\\Cosas TFG\\SWRL\\TFG_base3.owl");

					File f = copyFileOWL(f_orig,f_save);
					
					OWLOntology o =  man.loadOntologyFromOntologyDocument(f);

					IRI i = o.getOntologyID().getOntologyIRI().get();
					String base = i.toString();
		for(int j = 0; j < tmp.length; j++) {
			// Prueba basica para comprobar cuanto tarda
			base_test(o, base, man, df, individuos[j], j);
		}
        for(int j = 0; j < tmp.length; j++) {
        	System.out.println(individuos[j] + "    " + tmp[j] + "\n");
		}
	}
}
