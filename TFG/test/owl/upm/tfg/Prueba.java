package owl.upm.tfg;

import static org.junit.Assert.*;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.jena.ontology.Individual;
import org.apache.jena.ontology.OntClass;
import org.apache.jena.ontology.OntModel;
import org.apache.jena.ontology.OntModelSpec;
import org.apache.jena.ontology.OntProperty;
import org.apache.jena.ontology.OntResource;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.NodeIterator;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.riot.RDFDataMgr;
import org.junit.Test;
import org.topbraid.spin.util.JenaUtil;

import junit.framework.AssertionFailedError;

public class Prueba {
	
	Model n = RDFDataMgr.loadModel("C:\\Users\\gonca\\Desktop\\Jaime Castro\\Cosas TFG\\TFG_base.owl");
	OntModel ontModel = JenaUtil.createOntologyModel(OntModelSpec.OWL_MEM,n); //se carga el archivo en un ontModel
	
	SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    String uri = "http://www.semanticweb.org/tfg/Ontologia_TFG#";
	String uri2 = "http://www.co-ode.org/ontologies/ont.owl#";
    int noIndividuos = 3;
    String prob [] = {"3.0", "7.0", "5.0"}; //probabilidades e impactos de amenazas por anomalias
    String impa [] = {"8.0", "5.0", "6.0"};
    String probV [] = {"4.0", "5.0", "3.0", "4.0", "6.0", "5.0", "4.0"}; //probabilidades e impactos de amenazas por vulnerabilidades
    String impaV [] = {"7.0", "6.0", "4.0", "5.0", "5.0", "3.0", "5.0"};
    String probA [] = {"5.0", "6.0", "7.0", "6.0", "2.0", "2.0", "2.0", "2.0"}; //probabilidades e impactos de amenazas por vulnerabilidades
    String impaA [] = {"4.0", "1.0", "5.0", "2.0", "3.0", "3.0", "3.0", "3.0"};
    String classN [] = {"FW_", "BT_", "WF_"};
    
    //Anomalias
    OntClass clAnom1 = ontModel.getOntClass(uri + "Firewall_Anomaly");
    OntClass clAnom2 = ontModel.getOntClass(uri + "Bluetooth_Sensor_Anomaly");
    OntClass clAnom3 = ontModel.getOntClass(uri + "WiFi_Sensor_Anomaly");
    OntClass anCl [] = {clAnom1, clAnom2, clAnom3};
    Date fecha2 = new Date();
    
    //Amenazas
    OntClass clTh1 = ontModel.getOntClass(uri + "DeliberatedUnauthorizedAccess");
    OntClass clTh2 = ontModel.getOntClass(uri + "DenialOfService");
    OntClass clTh3 = ontModel.getOntClass(uri + "ConfigurationError");
    OntClass thCl [] = {clTh1, clTh2, clTh3};
    
    //Vulnerabilidad
    Individual r1 = ontModel.getIndividual(uri + "R1");
    Individual r2 = ontModel.getIndividual(uri + "R2");
    Individual r3 = ontModel.getIndividual(uri + "R3");
    Individual pc1 = ontModel.getIndividual(uri + "PC1");
    Individual pc2 = ontModel.getIndividual(uri + "PC2");
    Individual pc3 = ontModel.getIndividual(uri + "PC3");
    Individual pc4 = ontModel.getIndividual(uri + "PC4");
    OntClass clVulThRouter = ontModel.getOntClass(uri + "NetworkOutage"); //amenaza de routers
    String diminR1 = "NO_1";
    String diminR2 = "NO_2";
    String diminR3 = "NO_3";
    OntClass clVulThPC14 = ontModel.getOntClass(uri + "DenialOfService"); //amenaza de PC1 Y PC4
    String diminPC1 = "DS_1";
    String diminPC4 = "DS_2";
    OntClass clVulThPC2 = ontModel.getOntClass(uri + "SWVulnerabilities"); //amenaza de PC2
    String diminPC2 = "SWV_1";
    OntClass clVulThPC3 = ontModel.getOntClass(uri + "MonitoringError"); //amenaza de PC3
    String diminPC3 = "ME_1";

    //AssetThreats
    OntClass clAsTh1 = ontModel.getOntClass(uri + "DeviceTheft"); //amenaza de robo que afecta a todos los ordenadores y un movil
    String dimin1 = "DT_1";
    String dimin2 = "DT_2";
    String dimin3 = "DT_3";
    String dimin4 = "DT_4";
    String dimin5 = "DT_5";
    Individual m1 = ontModel.getIndividual(uri + "M1");
    OntClass clAsTh2 = ontModel.getOntClass(uri + "DeviceLost"); //amenaza de perdida que afecta a dos ordenadores y un movil
    String diminl1 = "DL_1";
    String diminl2 = "DL_2";
    String diminl3 = "DL_3";
    Individual m2 = ontModel.getIndividual(uri + "M2");
    OntClass clAsThIt = ontModel.getOntClass(uri + "IdentityThief"); //amenaza de robo de identidad que afecta a un usuario
    String dimint1 = "IT_1";
    Individual u1 = ontModel.getIndividual(uri + "U1");
    OntClass clAsThNon = ontModel.getOntClass(uri + "NonIntentionalUserError"); //amenaza erro no intencional de un usuario
    String diminn1 = "NUE_1";
    Individual u2 = ontModel.getIndividual(uri + "U2");
    OntClass clAsThUs = ontModel.getOntClass(uri + "UsersComplaints"); //amenaza de problemas de un usuario
    String diminu1 = "UC_1";
    Individual u3 = ontModel.getIndividual(uri + "U3");
    OntClass clAsThSo = ontModel.getOntClass(uri + "SocialEngineering"); //amenaza de ingenieria social a un usuario
    String dimins1 = "SE_1";
    Individual u4 = ontModel.getIndividual(uri + "U4");

    //Metodos
    MetodosInicio inicio = new MetodosInicio();
    MetodosEliminacion eliminacion = new MetodosEliminacion();

    //Generacion anomalias
	@Test
	public void testGenAn() {
        String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Detected_Anomaly ." +
		            "  }\n";

		List<QuerySolution> var = new ArrayList<QuerySolution>();
		ResultSet select1 = QueryExecutionFactory.create(QueryFactory.create(c2), ontModel).execSelect();
		int resultado1 = 0;
		for(; select1.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = select1.next();
	    	var.add(aux); 
		}
        assertEquals(resultado1, var.size());	
        var.clear();
        
        inicio.genAn(classN, anCl, noIndividuos, fecha2, fecha2, uri, ontModel);
        int resultado2 = 9;
        ResultSet select2 = QueryExecutionFactory.create(QueryFactory.create(c2), ontModel).execSelect(); 
        for(;select2.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = select2.next();
	    	var.add(aux); 
	    }
        
        assertEquals(resultado2, var.size());
        boolean pru = false;
        for(QuerySolution q : var) {
        	String anom = ontModel.getIndividual(q.get("s").toString()).getOntClass(true).toString();
        	for(OntClass n : anCl) {
        		if(anom.equals(n.toString())) {
        			assertEquals(anom, n.toString());
        			pru = !pru;
        		}
        	}
        }
        assertTrue(pru);
	}

	//Generacion amenazas por anomalias
	@Test
	public void testGenTh() {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Threat ." +
		            "  }\n";
		String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Detected_Anomaly ." +
		            "  }\n";

	    inicio.genAn(classN, anCl, noIndividuos, fecha2, fecha2, uri, ontModel);
	    OntProperty generates = ontModel.getOntProperty(uri2 + "generates");
	    OntProperty isGen = ontModel.getOntProperty(uri2 + "isGeneratedBy");
	    OntProperty p = ontModel.getOntProperty(uri + "probability");
	    OntProperty i = ontModel.getOntProperty(uri + "impact");
		List<QuerySolution> varTh = new ArrayList<QuerySolution>();
		List<QuerySolution> varAn = new ArrayList<QuerySolution>();
		ResultSet selectTh1 = QueryExecutionFactory.create(QueryFactory.create(c2), ontModel).execSelect();
		int resultado1 = 0;
		for(; selectTh1.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = selectTh1.next();
	    	varTh.add(aux); 
		}
		ResultSet selectAn = QueryExecutionFactory.create(QueryFactory.create(c3), ontModel).execSelect();
		for(; selectAn.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = selectAn.next();
	    	varAn.add(aux); 
		}
		for(QuerySolution q : varAn) {
			Individual anom = ontModel.getIndividual(q.get("s").toString());
			assertFalse(anom.hasProperty(generates));
		}
        assertEquals(resultado1, varTh.size());	
        varTh.clear();
        inicio.genTh(prob, impa, classN, thCl, noIndividuos, uri, uri2, ontModel);
        int resultado2 = 9;
        ResultSet selectTh2 = QueryExecutionFactory.create(QueryFactory.create(c2), ontModel).execSelect(); 
        for(;selectTh2.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = selectTh2.next();
	    	varTh.add(aux); 
	    }
        for(QuerySolution q : varAn) {
			Individual anom = ontModel.getIndividual(q.get("s").toString());
			assertTrue(anom.hasProperty(generates));
		}
        for(QuerySolution q : varTh) {
			Individual th = ontModel.getIndividual(q.get("s").toString());
			assertTrue(th.hasProperty(isGen));
		}
        for(QuerySolution q : varAn) {
			String anTh = ontModel.getIndividual(q.get("s").toString()).getPropertyValue(generates).toString();
			for(QuerySolution u : varTh) {
				String th = ontModel.getIndividual(q.get("s").toString()).toString();
				if(anTh.equals(th)) {
					assertEquals(anTh, th);
				}
			}
		}
        for(QuerySolution q : varTh) {
			String thAn = ontModel.getIndividual(q.get("s").toString()).getPropertyValue(isGen).toString();
			for(QuerySolution u : varAn) {
				String an = ontModel.getIndividual(q.get("s").toString()).toString();
				if(thAn.equals(an)) {
					assertEquals(thAn, an);
				}
			}
		}
        assertEquals(resultado2, varTh.size(), 0.01);
        for(QuerySolution q : varTh) {
        	String th = ontModel.getIndividual(q.get("s").toString()).getOntClass(true).toString();
        	for(OntClass n : thCl) {
        		if(th.equals(n.toString())) {
        			assertEquals(th, n.toString());
        		}
        	}
        }
        for(QuerySolution q : varTh) {
        	String th = ontModel.getIndividual(q.get("s").toString()).getOntClass(true).toString();
        	String pr = ontModel.getIndividual(q.get("s").toString()).getPropertyValue(p).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
        	String im = ontModel.getIndividual(q.get("s").toString()).getPropertyValue(i).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
        	if(pr.equals("3.0") && im.equals("8.0")) {
        		assertEquals(th, thCl[0].toString());
        	}
        	else if(pr.equals("7.0") && im.equals("5.0")) {
        		assertEquals(th, thCl[1].toString());
        	}
        	else if(pr.equals("5.0") && im.equals("6.0")) {
        		assertEquals(th, thCl[2].toString());
        	} else {
        		fail();
        	}
        }
	}

    //Generacion de riesgos y salvaguardas
	@Test
	public void testGenRs() {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Risk ." +
		            "  }\n";
		String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Threat ." +
		            "  }\n";
		OntProperty isGenBy = ontModel.getOntProperty(uri2 + "isGeneratedBy");
		OntProperty generates = ontModel.getOntProperty(uri2 + "generates");
		List<QuerySolution> varTh = new ArrayList<QuerySolution>();
		List<QuerySolution> var = new ArrayList<QuerySolution>();
		ResultSet select1 = QueryExecutionFactory.create(QueryFactory.create(c2), ontModel).execSelect();
		for(; select1.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = select1.next();
	    	var.add(aux); 
		}
		for(QuerySolution q : var) {
			Individual auxIn = ontModel.getIndividual(q.get("s").toString());
			assertFalse(auxIn.hasProperty(isGenBy));
		}   
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r1, clVulThRouter, diminR1, probV[0], impaV[0], uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, diminR2, probV[1], impaV[1], uri, uri2, ontModel);
		inicio.genVul(r3, clVulThRouter, diminR3, probV[2], impaV[2], uri, uri2, ontModel);
		inicio.genVul(pc1, clVulThPC14, diminPC1, probV[3], impaV[3], uri, uri2, ontModel);
		inicio.genVul(pc2, clVulThPC2, diminPC2, probV[4], impaV[4], uri, uri2, ontModel);
		inicio.genVul(pc3, clVulThPC3, diminPC3, probV[5], impaV[5], uri, uri2, ontModel);
		inicio.genVul(pc4, clVulThPC14, diminPC4, probV[6], impaV[6], uri, uri2, ontModel);
		inicio.genAssetTh(pc1, clAsTh1, dimin1, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc2, clAsTh1, dimin2, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc3, clAsTh1, dimin3, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh1, dimin4, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc1, clAsTh2, diminl1, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh2, diminl2, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(m1, clAsTh1, dimin5, probA[2], impaA[2], uri, ontModel);
		inicio.genAssetTh(m2, clAsTh2, diminl3, probA[3], impaA[3], uri, ontModel);
		inicio.genAssetTh(u1, clAsThIt, dimint1, probA[4], impaA[4], uri, ontModel);
		inicio.genAssetTh(u2, clAsThNon, diminn1, probA[5], impaA[5], uri, ontModel);
		inicio.genAssetTh(u3, clAsThUs, diminu1, probA[6], impaA[6], uri, ontModel);
		inicio.genAssetTh(u4, clAsThSo, dimins1, probA[7], impaA[7], uri, ontModel);
		ResultSet selectTh1 = QueryExecutionFactory.create(QueryFactory.create(c3), ontModel).execSelect();
		for(; selectTh1.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = selectTh1.next();
	    	varTh.add(aux); 
		}
		for(QuerySolution q : varTh) {
			Individual th = ontModel.getIndividual(q.get("s").toString());
			assertFalse(th.hasProperty(generates));
		}
		for(QuerySolution q : var) {
			Individual auxIn = ontModel.getIndividual(q.get("s").toString());
			assertFalse(auxIn.hasProperty(isGenBy));
		}   
        inicio.genRs(ontModel, uri);
        for(QuerySolution q : varTh) {
			Individual th = ontModel.getIndividual(q.get("s").toString());
			assertTrue(th.hasProperty(generates));
			String cl = ontModel.getIndividual(q.get("s").toString()).getOntClass(true).toString();
			String rs = ontModel.getIndividual(q.get("s").toString()).getPropertyValue(generates).toString();
			assertEquals(cl + "Risk_Risk", rs);
			assertTrue(ontModel.getIndividual(cl + "Risk_Risk").hasProperty(isGenBy));
		}
        OntProperty rv = ontModel.getOntProperty(uri + "risk_value");
        OntProperty rvp = ontModel.getOntProperty(uri + "potential_risk_value");
        Individual [] ris = { ontModel.getIndividual(uri + "NetworkOutageRisk_Risk"), ontModel.getIndividual(uri + "DenialOfServiceRisk_Risk"), ontModel.getIndividual(uri + "DeviceLostRisk_Risk"),
        		ontModel.getIndividual(uri + "DeviceTheftRisk_Risk"), ontModel.getIndividual(uri + "MonitoringErrorRisk_Risk"), ontModel.getIndividual(uri + "SWVulnerabilitiesRisk_Risk"), ontModel.getIndividual(uri + "NonIntentionalUserErrorRisk_Risk"), 
        		ontModel.getIndividual(uri + "UsersComplaintsRisk_Risk"), ontModel.getIndividual(uri + "IdentityThiefRisk_Risk"), ontModel.getIndividual(uri + "SocialEngineeringRisk_Risk") };
        String [] val1 = { "18.333334", "10.0", "8.0", "23.0", "15.0", "30.0", "6.0", "6.0", "6.0", "6.0" };
        String [] val2 = { "23.333334", "20.0", "8.0", "23.0", "15.0", "30.0", "6.0", "6.0", "6.0", "6.0" };
        for(int i = 0; i < ris.length; i++) {
			assertEquals(ris[i].getPropertyValue(rv).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", ""), val1[i]);
			assertEquals(ris[i].getPropertyValue(rvp).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", ""), val2[i]);
		} 
        
        inicio.genAn(classN, anCl, noIndividuos, fecha2, fecha2, uri, ontModel);
        inicio.genTh(prob, impa, classN, thCl, noIndividuos, uri, uri2, ontModel);
        varTh.clear();
        ResultSet selectTh2 = QueryExecutionFactory.create(QueryFactory.create(c3), ontModel).execSelect();
		for(; selectTh2.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = selectTh2.next();
	    	varTh.add(aux); 
		}
        inicio.genRs(ontModel, uri);
        for(QuerySolution q : varTh) {
			Individual th = ontModel.getIndividual(q.get("s").toString());
			assertTrue(th.hasProperty(generates));
			String cl = ontModel.getIndividual(q.get("s").toString()).getOntClass(true).toString();
			String rs = ontModel.getIndividual(q.get("s").toString()).getPropertyValue(generates).toString();
			assertEquals(cl + "Risk_Risk", rs);
			assertTrue(ontModel.getIndividual(cl + "Risk_Risk").hasProperty(isGenBy));
		}
        assertEquals(ris[1].getPropertyValue(rv).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", ""), "19.0");
        assertEquals(ris[1].getPropertyValue(rvp).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", ""), "29.0");
	}

	//Prueba generacion amenazas debidas a vulnerabilidades
	@Test
	public void testGenVul() {
		OntProperty hasVul = ontModel.getOntProperty(uri2 + "has_vulnerability");
		OntProperty isExp = ontModel.getOntProperty(uri2 + "isExposedTo");	
		OntProperty exp = ontModel.getOntProperty(uri + "exposesTo");
		OntProperty p = ontModel.getOntProperty(uri + "probability");	
		OntProperty im = ontModel.getOntProperty(uri + "impact");	
		for(int i = 1; i <= 7; i++) {
			assertFalse(ontModel.getIndividual(uri + "V" + i).hasProperty(exp));
		}
		assertFalse(r1.hasProperty(hasVul));
		assertFalse(r1.hasProperty(isExp));
		assertFalse(r2.hasProperty(hasVul));
		assertFalse(r2.hasProperty(isExp));
		assertFalse(r3.hasProperty(hasVul));
		assertFalse(r3.hasProperty(isExp));
		assertFalse(pc1.hasProperty(hasVul));
		assertFalse(pc1.hasProperty(isExp));
		assertFalse(pc2.hasProperty(hasVul));
		assertFalse(pc2.hasProperty(isExp));
		assertFalse(pc3.hasProperty(hasVul));
		assertFalse(pc3.hasProperty(isExp));
		assertFalse(pc4.hasProperty(hasVul));
		assertFalse(pc4.hasProperty(isExp));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminR1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminR2));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminR3));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminPC1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminPC2));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminPC3));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminPC4));
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r1, clVulThRouter, diminR1, probV[0], impaV[0], uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, diminR2, probV[1], impaV[1], uri, uri2, ontModel);
		inicio.genVul(r3, clVulThRouter, diminR3, probV[2], impaV[2], uri, uri2, ontModel);
		inicio.genVul(pc1, clVulThPC14, diminPC1, probV[3], impaV[3], uri, uri2, ontModel);
		inicio.genVul(pc2, clVulThPC2, diminPC2, probV[4], impaV[4], uri, uri2, ontModel);
		inicio.genVul(pc3, clVulThPC3, diminPC3, probV[5], impaV[5], uri, uri2, ontModel);
		inicio.genVul(pc4, clVulThPC14, diminPC4, probV[6], impaV[6], uri, uri2, ontModel);
		Individual [] th = {ontModel.getIndividual(uri + "Threat_" + diminR1), ontModel.getIndividual(uri + "Threat_" + diminR2), ontModel.getIndividual(uri + "Threat_" + diminR3),
				ontModel.getIndividual(uri + "Threat_" + diminPC1), ontModel.getIndividual(uri + "Threat_" + diminPC2), ontModel.getIndividual(uri + "Threat_" + diminPC3),
				ontModel.getIndividual(uri + "Threat_" + diminPC4)};
	    for(int i = 0; i < 7; i++) {
	    	assertTrue(th[i].getPropertyValue(p).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(probV[i]) && th[i].getPropertyValue(im).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(impaV[i]));
	    }
		assertEquals(ontModel.getIndividual(uri + "V1").toString(), r1.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V5").toString(), r2.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V6").toString(), r3.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V2").toString(), pc1.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V3").toString(), pc2.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V4").toString(), pc3.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V2").toString(), pc4.getPropertyValue(hasVul).toString());	
		
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminR1).toString(), r1.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminR2).getURI(), r2.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminR3).getURI(), r3.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminPC1).getURI(), pc1.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminPC2).getURI(), pc2.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminPC3).getURI(), pc3.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminPC4).getURI(), pc4.getPropertyValue(isExp).toString());	
		
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminR1).toString(), ontModel.getIndividual(r1.getPropertyValue(hasVul).toString()).getPropertyValue(exp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminR2).getURI(), ontModel.getIndividual(r2.getPropertyValue(hasVul).toString()).getPropertyValue(exp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminR3).getURI(), ontModel.getIndividual(r3.getPropertyValue(hasVul).toString()).getPropertyValue(exp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminPC2).getURI(), ontModel.getIndividual(pc2.getPropertyValue(hasVul).toString()).getPropertyValue(exp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminPC3).getURI(), ontModel.getIndividual(pc3.getPropertyValue(hasVul).toString()).getPropertyValue(exp).toString());	

		assertFalse(ontModel.getIndividual(uri + "V7").hasProperty(exp));
		
		String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s \n" +
		            "WHERE\n" +
		            "  { Ontologia_TFG:V2 Ontologia_TFG:exposesTo ?s ." +
		            "  }\n";
		List<QuerySolution> var = new ArrayList<QuerySolution>();
		ResultSet select1 = QueryExecutionFactory.create(QueryFactory.create(c3), ontModel).execSelect();
		for(; select1.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = select1.next();
	    	var.add(aux); 
		}
		for(QuerySolution q : var) {
			String x = q.get("s").toString();
			if(x.equals(ontModel.getIndividual(uri + "Threat_" + diminPC1).getURI()) || x.equals(ontModel.getIndividual(uri + "Threat_" + diminPC4).getURI())) {
				
			} else {
				fail();
			}
		}
	}
	
	//Generacion de amenazas a partir de actvios por si mismos
	@Test
	public void testGenAsset() {
		OntProperty isExp = ontModel.getOntProperty(uri2 + "isExposedTo");	
		OntProperty p = ontModel.getOntProperty(uri + "probability");	
		OntProperty im = ontModel.getOntProperty(uri + "impact");	
		assertFalse(pc1.hasProperty(isExp));
		assertFalse(pc2.hasProperty(isExp));
		assertFalse(pc3.hasProperty(isExp));
		assertFalse(pc4.hasProperty(isExp));
		assertFalse(m1.hasProperty(isExp));
		assertFalse(m2.hasProperty(isExp));
		assertFalse(u1.hasProperty(isExp));
		assertFalse(u2.hasProperty(isExp));
		assertFalse(u3.hasProperty(isExp));
		assertFalse(u4.hasProperty(isExp));
		assertNull(ontModel.getIndividual(uri + "Threat_" + dimin1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + dimin2));
		assertNull(ontModel.getIndividual(uri + "Threat_" + dimin3));
		assertNull(ontModel.getIndividual(uri + "Threat_" + dimin4));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminl1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminl2));
		assertNull(ontModel.getIndividual(uri + "Threat_" + dimin5));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminl3));
		assertNull(ontModel.getIndividual(uri + "Threat_" + dimint1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminn1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminu1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + dimins1));
		inicio.genAssetTh(pc1, clAsTh1, dimin1, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc2, clAsTh1, dimin2, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc3, clAsTh1, dimin3, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh1, dimin4, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc1, clAsTh2, diminl1, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh2, diminl2, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(m1, clAsTh1, dimin5, probA[2], impaA[2], uri, ontModel);
		inicio.genAssetTh(m2, clAsTh2, diminl3, probA[3], impaA[3], uri, ontModel);
		inicio.genAssetTh(u1, clAsThIt, dimint1, probA[4], impaA[4], uri, ontModel);
		inicio.genAssetTh(u2, clAsThNon, diminn1, probA[5], impaA[5], uri, ontModel);
		inicio.genAssetTh(u3, clAsThUs, diminu1, probA[6], impaA[6], uri, ontModel);
		inicio.genAssetTh(u4, clAsThSo, dimins1, probA[7], impaA[7], uri, ontModel);
		Individual [] th = { ontModel.getIndividual(uri + "Threat_" + dimin1), ontModel.getIndividual(uri + "Threat_" + dimin2),
				ontModel.getIndividual(uri + "Threat_" + dimin3), ontModel.getIndividual(uri + "Threat_" + dimin4), ontModel.getIndividual(uri + "Threat_" + diminl1), 
				ontModel.getIndividual(uri + "Threat_" + diminl2), ontModel.getIndividual(uri + "Threat_" + dimin5), ontModel.getIndividual(uri + "Threat_" + diminl3),
				ontModel.getIndividual(uri + "Threat_" + dimint1), ontModel.getIndividual(uri + "Threat_" + diminn1), ontModel.getIndividual(uri + "Threat_" + diminu1),
				ontModel.getIndividual(uri + "Threat_" + dimins1) };
		int aux1 = 0;
		int aux2 = 2;
		for(Individual q : th) {
			if(aux1 < 4) {
				assertTrue(q.getPropertyValue(p).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(probA[0]) && q.getPropertyValue(im).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(impaA[0]));
				aux1++;
			} else if(aux1 >= 4 && aux1 < 6) {
				assertTrue(q.getPropertyValue(p).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(probA[1]) && q.getPropertyValue(im).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(impaA[1]));
				aux1++;
			} else {
				assertTrue(q.getPropertyValue(p).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(probA[aux2]) && q.getPropertyValue(im).toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "").equals(impaA[aux2]));
				aux2++;
			}
		}
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimin2).toString(), pc2.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimin3).getURI(), pc3.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimin5).getURI(), m1.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminl3).getURI(), m2.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimint1).getURI(), u1.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminn1).getURI(), u2.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminu1).getURI(), u3.getPropertyValue(isExp).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimins1).getURI(), u4.getPropertyValue(isExp).toString());
		String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s ?u \n" +
		            "WHERE\n" +
		            "  { Ontologia_TFG:PC1 Ontologia_TFG:isExposedTo ?s ." +
		            "    Ontologia_TFG:PC4 Ontologia_TFG:isExposedTo ?u ." +
		            "  }\n";
		List<QuerySolution> var = new ArrayList<QuerySolution>();
		ResultSet select1 = QueryExecutionFactory.create(QueryFactory.create(c3), ontModel).execSelect();
		for(; select1.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = select1.next();
	    	var.add(aux); 
		}
		for(QuerySolution q : var) {
			String x = q.get("s").toString();
			String y = q.get("u").toString();
			if(x.equals(ontModel.getIndividual(uri + "Threat_" + dimin1).getURI()) || x.equals(ontModel.getIndividual(uri + "Threat_" + diminl1).getURI())) {
				
			} else {
				fail();
			}
            if(y.equals(ontModel.getIndividual(uri + "Threat_" + dimin4).getURI()) || y.equals(ontModel.getIndividual(uri + "Threat_" + diminl2).getURI())) {
				
			} else {
				fail();
			}
		}
	}
	
//Prueba de calculo de riesgo total
	@Test
	public void testTotalRiskBeginning() {
		float [] resultados = inicio.totalRisk(ontModel);
		float resultadoEsperado = 0.0f;
		assertEquals(resultadoEsperado, resultados[0], 0.01);
		assertEquals(resultadoEsperado, resultados[1], 0.01);
	}

	@Test
	public void testTotalRiskWithVulAndAsset() {
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r1, clVulThRouter, diminR1, probV[0], impaV[0], uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, diminR2, probV[1], impaV[1], uri, uri2, ontModel);
		inicio.genVul(r3, clVulThRouter, diminR3, probV[2], impaV[2], uri, uri2, ontModel);
		inicio.genVul(pc1, clVulThPC14, diminPC1, probV[3], impaV[3], uri, uri2, ontModel);
		inicio.genVul(pc2, clVulThPC2, diminPC2, probV[4], impaV[4], uri, uri2, ontModel);
		inicio.genVul(pc3, clVulThPC3, diminPC3, probV[5], impaV[5], uri, uri2, ontModel);
		inicio.genVul(pc4, clVulThPC14, diminPC4, probV[6], impaV[6], uri, uri2, ontModel);
		inicio.genAssetTh(pc1, clAsTh1, dimin1, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc2, clAsTh1, dimin2, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc3, clAsTh1, dimin3, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh1, dimin4, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc1, clAsTh2, diminl1, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh2, diminl2, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(m1, clAsTh1, dimin5, probA[2], impaA[2], uri, ontModel);
		inicio.genAssetTh(m2, clAsTh2, diminl3, probA[3], impaA[3], uri, ontModel);
		inicio.genAssetTh(u1, clAsThIt, dimint1, probA[4], impaA[4], uri, ontModel);
		inicio.genAssetTh(u2, clAsThNon, diminn1, probA[5], impaA[5], uri, ontModel);
		inicio.genAssetTh(u3, clAsThUs, diminu1, probA[6], impaA[6], uri, ontModel);
		inicio.genAssetTh(u4, clAsThSo, dimins1, probA[7], impaA[7], uri, ontModel);
		inicio.genRs(ontModel, uri);
		float [] resultados = inicio.totalRisk(ontModel);
		float resultadoEsperado = 14.333333f;
		float resultadoEsperado2 = 12.833334f;
		assertEquals(resultadoEsperado, resultados[0], 0.01);
		assertEquals(resultadoEsperado2, resultados[1], 0.01);
	}
		
	@Test
	public void testTotalRiskWithVulAssetAndAnomalies() throws ParseException {
		Date fecha1 = dateFormat.parse("2021-05-01");
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r1, clVulThRouter, diminR1, probV[0], impaV[0], uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, diminR2, probV[1], impaV[1], uri, uri2, ontModel);
		inicio.genVul(r3, clVulThRouter, diminR3, probV[2], impaV[2], uri, uri2, ontModel);
		inicio.genVul(pc1, clVulThPC14, diminPC1, probV[3], impaV[3], uri, uri2, ontModel);
		inicio.genVul(pc2, clVulThPC2, diminPC2, probV[4], impaV[4], uri, uri2, ontModel);
		inicio.genVul(pc3, clVulThPC3, diminPC3, probV[5], impaV[5], uri, uri2, ontModel);
		inicio.genVul(pc4, clVulThPC14, diminPC4, probV[6], impaV[6], uri, uri2, ontModel);
		inicio.genAssetTh(pc1, clAsTh1, dimin1, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc2, clAsTh1, dimin2, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc3, clAsTh1, dimin3, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh1, dimin4, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc1, clAsTh2, diminl1, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh2, diminl2, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(m1, clAsTh1, dimin5, probA[2], impaA[2], uri, ontModel);
		inicio.genAssetTh(m2, clAsTh2, diminl3, probA[3], impaA[3], uri, ontModel);
		inicio.genAssetTh(u1, clAsThIt, dimint1, probA[4], impaA[4], uri, ontModel);
		inicio.genAssetTh(u2, clAsThNon, diminn1, probA[5], impaA[5], uri, ontModel);
		inicio.genAssetTh(u3, clAsThUs, diminu1, probA[6], impaA[6], uri, ontModel);
		inicio.genAssetTh(u4, clAsThSo, dimins1, probA[7], impaA[7], uri, ontModel);
		inicio.genAn(classN, anCl, noIndividuos, fecha1, fecha2, uri, ontModel);
		inicio.genTh(prob, impa, classN, thCl, noIndividuos, uri, uri2, ontModel);
		inicio.genRs(ontModel, uri);
		float [] resultados = inicio.totalRisk(ontModel);
		float resultadoEsperado = 17.194445f;
		float resultadoEsperado2 = 15.944444f;
		assertEquals(resultadoEsperado, resultados[0], 0.01);
		assertEquals(resultadoEsperado2, resultados[1], 0.01);
	}
	
	@Test
	public void testTotalRiskAfterEliminationSomeThreats() throws ParseException {
		Date fecha1 = dateFormat.parse("2021-05-01");
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r1, clVulThRouter, diminR1, probV[0], impaV[0], uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, diminR2, probV[1], impaV[1], uri, uri2, ontModel);
		inicio.genVul(r3, clVulThRouter, diminR3, probV[2], impaV[2], uri, uri2, ontModel);
		inicio.genVul(pc1, clVulThPC14, diminPC1, probV[3], impaV[3], uri, uri2, ontModel);
		inicio.genVul(pc2, clVulThPC2, diminPC2, probV[4], impaV[4], uri, uri2, ontModel);
		inicio.genVul(pc3, clVulThPC3, diminPC3, probV[5], impaV[5], uri, uri2, ontModel);
		inicio.genVul(pc4, clVulThPC14, diminPC4, probV[6], impaV[6], uri, uri2, ontModel);
		inicio.genAssetTh(pc1, clAsTh1, dimin1, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc2, clAsTh1, dimin2, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc3, clAsTh1, dimin3, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh1, dimin4, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc1, clAsTh2, diminl1, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh2, diminl2, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(m1, clAsTh1, dimin5, probA[2], impaA[2], uri, ontModel);
		inicio.genAssetTh(m2, clAsTh2, diminl3, probA[3], impaA[3], uri, ontModel);
		inicio.genAssetTh(u1, clAsThIt, dimint1, probA[4], impaA[4], uri, ontModel);
		inicio.genAssetTh(u2, clAsThNon, diminn1, probA[5], impaA[5], uri, ontModel);
		inicio.genAssetTh(u3, clAsThUs, diminu1, probA[6], impaA[6], uri, ontModel);
		inicio.genAssetTh(u4, clAsThSo, dimins1, probA[7], impaA[7], uri, ontModel);
		inicio.genAn(classN, anCl, noIndividuos, fecha1, fecha2, uri, ontModel);
		inicio.genTh(prob, impa, classN, thCl, noIndividuos, uri, uri2, ontModel);
		inicio.genRs(ontModel, uri);
		eliminacion.eliminate(ontModel, 4, uri);
	    inicio.calRsV(ontModel, uri);
	    float [] resultados = inicio.totalRisk(ontModel);
		float resultadoEsperado = 15.233333f;
		float resultadoEsperado2 = 13.733335f;
		assertEquals(resultadoEsperado, resultados[0], 0.01);
		assertEquals(resultadoEsperado2, resultados[1], 0.01);
		r1.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("H1.5"));
		r2.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("Cis1.5"));
		pc1.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("W2.0"));
		pc4.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("W2.0"));
		eliminacion.changeAsset(ontModel);
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, "NO_4", "3.0", "5.0", uri, uri2, ontModel);
		inicio.genRs(ontModel, uri);
		float [] resultados2 = inicio.totalRisk(ontModel);
		float resultadoEsperado12 = 14.85f;
	    float resultadoEsperado22 = 13.35f;
		assertEquals(resultadoEsperado12, resultados2[0], 0.01);
		assertEquals(resultadoEsperado22, resultados2[1], 0.01);
	}
	
	//Eliminacion anomalias
	@Test
	public void testAnomaliesElimination() throws ParseException {
		OntProperty generates = ontModel.getOntProperty(uri2 + "generates");
		Date fecha1 = dateFormat.parse("2021-05-01");
		inicio.genAn(classN, anCl, noIndividuos, fecha1, fecha2, uri, ontModel);
		inicio.genTh(prob, impa, classN, thCl, noIndividuos, uri, uri2, ontModel);
		inicio.genRs(ontModel, uri);
		eliminacion.eliminate(ontModel, 4, uri);
		assertNull(ontModel.getIndividual(uri + "Anomaly_FW_0"));
		assertNull(ontModel.getIndividual(uri + "Anomaly_FW_1"));
		assertNull(ontModel.getIndividual(uri + "Anomaly_FW_2"));
		assertNull(ontModel.getIndividual(uri + "Anomaly_WF_0"));
		assertNull(ontModel.getIndividual(uri + "Anomaly_WF_1"));
		assertNull(ontModel.getIndividual(uri + "Anomaly_WF_2"));
		assertNull(ontModel.getIndividual(uri + "Threat_FW_0"));
		assertNull(ontModel.getIndividual(uri + "Threat_FW_1"));
		assertNull(ontModel.getIndividual(uri + "Threat_FW_2"));
		assertNull(ontModel.getIndividual(uri + "Threat_WF_0"));
		assertNull(ontModel.getIndividual(uri + "Threat_WF_1"));
		assertNull(ontModel.getIndividual(uri + "Threat_WF_2"));
		assertNotNull(ontModel.getIndividual(uri + "Anomaly_BT_0"));
		assertNotNull(ontModel.getIndividual(uri + "Anomaly_BT_1"));
		assertNotNull(ontModel.getIndividual(uri + "Anomaly_BT_2"));
		assertNotNull(ontModel.getIndividual(uri + "Threat_BT_0"));
		assertNotNull(ontModel.getIndividual(uri + "Threat_BT_1"));
		assertNotNull(ontModel.getIndividual(uri + "Threat_BT_2"));
		assertEquals(ontModel.getIndividual(uri + "Anomaly_BT_0").getPropertyValue(generates).toString(), ontModel.getIndividual(uri + "Threat_BT_0").toString());
		assertEquals(ontModel.getIndividual(uri + "Anomaly_BT_1").getPropertyValue(generates).toString(), ontModel.getIndividual(uri + "Threat_BT_1").toString());
		assertEquals(ontModel.getIndividual(uri + "Anomaly_BT_2").getPropertyValue(generates).toString(), ontModel.getIndividual(uri + "Threat_BT_2").toString());
	}
	
	//Eliminacion de vulnerabilidades
	@Test
	public void testVulnerabilitiesElimination() {
		OntProperty hasVul = ontModel.getOntProperty(uri2 + "has_vulnerability");
		OntProperty isEx = ontModel.getOntProperty(uri2 + "isExposedTo");
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r1, clVulThRouter, diminR1, probV[0], impaV[0], uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, diminR2, probV[1], impaV[1], uri, uri2, ontModel);
		inicio.genVul(r3, clVulThRouter, diminR3, probV[2], impaV[2], uri, uri2, ontModel);
		inicio.genVul(pc1, clVulThPC14, diminPC1, probV[3], impaV[3], uri, uri2, ontModel);
		inicio.genVul(pc2, clVulThPC2, diminPC2, probV[4], impaV[4], uri, uri2, ontModel);
		inicio.genVul(pc3, clVulThPC3, diminPC3, probV[5], impaV[5], uri, uri2, ontModel);
		inicio.genVul(pc4, clVulThPC14, diminPC4, probV[6], impaV[6], uri, uri2, ontModel);
		inicio.genAssetTh(pc2, clAsTh1, dimin2, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc3, clAsTh1, dimin3, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh1, dimin4, probA[0], impaA[0], uri, ontModel);
		inicio.genAssetTh(pc1, clAsTh2, diminl1, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(pc4, clAsTh2, diminl2, probA[1], impaA[1], uri, ontModel);
		inicio.genAssetTh(m1, clAsTh1, dimin5, probA[2], impaA[2], uri, ontModel);
		inicio.genAssetTh(m2, clAsTh2, diminl3, probA[3], impaA[3], uri, ontModel);
		inicio.genAssetTh(u1, clAsThIt, dimint1, probA[4], impaA[4], uri, ontModel);
		inicio.genAssetTh(u2, clAsThNon, diminn1, probA[5], impaA[5], uri, ontModel);
		inicio.genAssetTh(u3, clAsThUs, diminu1, probA[6], impaA[6], uri, ontModel);
		inicio.genAssetTh(u4, clAsThSo, dimins1, probA[7], impaA[7], uri, ontModel);
		inicio.genRs(ontModel, uri);
		assertEquals(r2.getPropertyValue(hasVul).toString(), ontModel.getIndividual(uri + "V5").toString());
		assertTrue(r1.hasProperty(hasVul));
		assertTrue(pc1.hasProperty(hasVul));
		assertTrue(pc4.hasProperty(hasVul));
		r1.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("H1.5"));
		r2.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("Cis1.5"));
		pc1.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("W2.0"));
		pc4.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("W2.0"));
		eliminacion.changeAsset(ontModel);
		inicio.relationVul(uri, uri2, ontModel);
		inicio.genVul(r2, clVulThRouter, "NO_4", "3.0", "5.0", uri, uri2, ontModel);
		assertEquals(r2.getPropertyValue(hasVul).toString(), ontModel.getIndividual(uri + "V7").toString());
		assertEquals(r2.getPropertyValue(isEx).toString(), ontModel.getIndividual(uri + "Threat_NO_4").toString());
		assertFalse(r1.hasProperty(hasVul));
		assertFalse(pc1.hasProperty(hasVul));
		assertFalse(pc4.hasProperty(hasVul));
		assertFalse(r1.hasProperty(isEx));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminR1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminR2));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminPC1));
		assertNull(ontModel.getIndividual(uri + "Threat_" + diminPC4));
	
		assertNotNull(ontModel.getIndividual(uri + "Threat_" + diminR3));
		assertNotNull(ontModel.getIndividual(uri + "Threat_" + diminPC2));
		assertNotNull(ontModel.getIndividual(uri + "Threat_" + diminPC3));

		assertEquals(ontModel.getIndividual(uri + "V6").toString(), r3.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V3").toString(), pc2.getPropertyValue(hasVul).toString());
		assertEquals(ontModel.getIndividual(uri + "V4").toString(), pc3.getPropertyValue(hasVul).toString());	
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimin2).toString(), pc2.getPropertyValue(isEx).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimin3).getURI(), pc3.getPropertyValue(isEx).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimin5).getURI(), m1.getPropertyValue(isEx).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminl3).getURI(), m2.getPropertyValue(isEx).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimint1).getURI(), u1.getPropertyValue(isEx).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminn1).getURI(), u2.getPropertyValue(isEx).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + diminu1).getURI(), u3.getPropertyValue(isEx).toString());
		assertEquals(ontModel.getIndividual(uri + "Threat_" + dimins1).getURI(), u4.getPropertyValue(isEx).toString());
		String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s ?u \n" +
		            "WHERE\n" +
		            "  { Ontologia_TFG:PC1 Ontologia_TFG:isExposedTo ?s ." +
		            "    Ontologia_TFG:PC4 Ontologia_TFG:isExposedTo ?u ." +
		            "  }\n";
		List<QuerySolution> var = new ArrayList<QuerySolution>();
		ResultSet select1 = QueryExecutionFactory.create(QueryFactory.create(c3), ontModel).execSelect();
		for(; select1.hasNext() ;) {
			QuerySolution aux = null;   	
	    	aux = select1.next();
	    	var.add(aux); 
		}
		for(QuerySolution q : var) {
			String x = q.get("s").toString();
			String y = q.get("u").toString();
			if(x.equals(ontModel.getIndividual(uri + "Threat_" + dimin1).getURI()) || x.equals(ontModel.getIndividual(uri + "Threat_" + diminl1).getURI())) {
				
			} else {
				fail();
			}
            if(y.equals(ontModel.getIndividual(uri + "Threat_" + dimin4).getURI()) || y.equals(ontModel.getIndividual(uri + "Threat_" + diminl2).getURI())) {
				
			} else {
				fail();
			}
		}
	}
	/*
	//Tiempo de ejecución SPIN
	@Test
	public void testTiempoEjecucionSPIN() throws ParseException, FileNotFoundException {
		long tInicio, tFin;
		int individuos [] = { 5, 10, 30, 50, 70, 90, 100, 150, 200, 250, 500, 750, 1000 };
		long tmp[] = new long[13];
		for(int i = 0; i < individuos.length; i++) {
	    	Model n = RDFDataMgr.loadModel("C:\\Users\\gonca\\Desktop\\Jaime Castro\\Cosas TFG\\TFG_base.owl");
	    	OntModel ontModel = JenaUtil.createOntologyModel(OntModelSpec.OWL_MEM,n); //se carga el archivo en un ontModel
	    	
	        //Anomalias
	        OntClass clAnom1 = ontModel.getOntClass(uri + "Firewall_Anomaly");
	        OntClass clAnom2 = ontModel.getOntClass(uri + "Bluetooth_Sensor_Anomaly");
	        OntClass clAnom3 = ontModel.getOntClass(uri + "WiFi_Sensor_Anomaly");
	        OntClass anCl [] = {clAnom1, clAnom2, clAnom3};
	        Date fecha1 = dateFormat.parse("2021-05-01");
	        Date fecha2 = new Date();
	        
	        //Amenazas
	        OntClass clTh1 = ontModel.getOntClass(uri + "DeliberatedUnauthorizedAccess");
	        OntClass clTh2 = ontModel.getOntClass(uri + "DenialOfService");
	        OntClass clTh3 = ontModel.getOntClass(uri + "ConfigurationError");
	        OntClass thCl [] = {clTh1, clTh2, clTh3};
	    	inicio.genAn(classN, anCl, individuos[i], fecha1, fecha2, uri, ontModel);
	    	tInicio = System.currentTimeMillis();
	    	inicio.genTh(prob, impa, classN, thCl, individuos[i], uri, uri2, ontModel);
	        inicio.genRs(ontModel, uri);
	        try {
	        	FileOutputStream f = new FileOutputStream("C:\\Users\\gonca\\Desktop\\Jaime Castro\\Cosas TFG\\TFG_base2.owl");
	        	ontModel.write(f);
	        	} catch (Error e) {
	        	}
	        tFin = System.currentTimeMillis();
	        tmp[i] = tFin - tInicio;
	    }
	    
	    for(int j = 0; j < tmp.length; j++) {
	    	System.out.println(individuos[j] + "    " + tmp[j] + "\n");
		}
	}
 */
}
