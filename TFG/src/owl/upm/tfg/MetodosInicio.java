package owl.upm.tfg;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.apache.jena.ontology.Individual;
import org.apache.jena.ontology.OntClass;
import org.apache.jena.ontology.OntModel;
import org.apache.jena.ontology.OntProperty;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.query.ResultSetFormatter;
import org.apache.jena.rdf.model.Model;

public class MetodosInicio {
	
	public void genAn(String classN [], OntClass anCl [], int noInd, Date fecha1, Date fecha2, String uri, OntModel oM) {
		String aName = "Anomaly_";
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		String fechaT = dateFormat.format(fecha1);
		String fechaF = dateFormat.format(fecha2);
		OntProperty date = oM.getOntProperty(uri + "date");
	    boolean bool = false;
		
	    for(int i = 0; i < anCl.length; i++) {
	    	OntClass auxCl = anCl[i];
	    	bool = !bool;
	    	for(int j = 0; j < noInd; j++) {
	    		Individual an = oM.createIndividual(uri + aName + classN[i] + j, auxCl);
	    		if(bool) {
	    			an.addProperty(date, oM.createTypedLiteral(fechaT));
	    		} else {
	    			an.addProperty(date, oM.createTypedLiteral(fechaF));
	    		}
	    	}
    		instOf(auxCl.getURI(), "Detected_Anomaly", oM);
	    }
	}

	public void genTh(String prob [], String impa [], String classN [], OntClass thCl [], int noInd, String uri, String uri2, OntModel oM) {
		String aName = "Anomaly_";
		String tName = "Threat_";
        OntProperty p = oM.getOntProperty(uri + "probability");	   
	    for(int i = 0; i < thCl.length; i++) {
	    	OntClass auxCl = thCl[i];
	    	for(int j = 0; j < noInd; j++) {
	    		Individual an = oM.createIndividual(uri + tName + classN[i] + j, auxCl);
	    		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
	    				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
	    				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	    	            "CONSTRUCT\n" + "{ <" + an.getURI() + "> Ontologia2:isGeneratedBy <" + oM.getIndividual(uri + aName + classN[i] + j).getURI() + "> . " +
	    	            "   }\n" +
	    	            "WHERE\n" +
	    	            "  { <" + an.getURI() + "> a <" + auxCl.getURI() + "> .\n" +
	    	            "  }\n";
	    		Model construct1 = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execConstruct();
	    	    oM.add(construct1);
	    	    String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
	    				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
	    				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	    	            "CONSTRUCT\n" + "{ <" + oM.getIndividual(uri + aName + classN[i] + j).getURI() + "> Ontologia2:generates <" + an.getURI() + "> . " +
	    	            "   }\n" +
	    	            "WHERE\n" +
	    	            "  { <" + oM.getIndividual(uri + aName + classN[i] + j).getURI() + "> a Ontologia_TFG:Detected_Anomaly .\n" +
	    	            "  }\n";
	    		Model construct2 = QueryExecutionFactory.create(QueryFactory.create(c3), oM).execConstruct();
	    	    oM.add(construct2);
	    	}
    		instOf(auxCl.getURI(), "Threat", oM);  
    		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
					+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
					 "SELECT ?s \n" +
			            "WHERE\n" +
			            "  { ?s a <" + thCl[i].toString() + "> ." +
			            "  }\n";
	    	List<QuerySolution> var = new ArrayList<QuerySolution>();
	    	ResultSet select = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execSelect();
	    	for(;select.hasNext();) {	
		    	QuerySolution aux = null;   	
		    	aux = select.next();
		    	var.add(aux); 
		    }
	    	for(QuerySolution q : var) {
	    		String in = q.get("s").toString();
	    		if(!oM.getIndividual(in).hasProperty(p)) {
	    			genPaI(prob[i], impa[i], in, oM);
	    		}
	    	}
	    }
	}
	
	public void genRs(OntModel oM, String uri) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Threat ." +
		            "  }\n";
		
		List<QuerySolution> var = new ArrayList<QuerySolution>();
		List<String> clases = new ArrayList<String>();
		ResultSet select = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execSelect();
		for(;select.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = select.next();
	    	var.add(aux); 
	    }
		if(var.isEmpty()) {
			System.out.println("No hay amenazas en el sistema.");
			return;
		}
		for(int i = 0; i < var.size(); i++) {
			String auxCl = oM.getIndividual(var.get(i).get("s").toString()).getOntClass(true).getURI();
			if(!clases.contains(auxCl)) {
				clases.add(auxCl);
				isGenBy(auxCl + "Risk_Risk", auxCl, oM); 
				generates(auxCl + "Risk_Risk", auxCl, oM);
			}
		}
		calRsV(oM, uri);
	}
	
	public void calRsV(OntModel oM, String uri) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
				 "SELECT ?s ?i ?p \n" +
		            "WHERE\n" +
		            "  { ?o a Ontologia_TFG:Threat ."
		            + "?s a Ontologia_TFG:Risk ."
		            + " ?s Ontologia2:isGeneratedBy ?o ." +
		              " ?o Ontologia_TFG:impact ?i ."
		             + " ?o Ontologia_TFG:probability ?p ." +
		            "  }\n";
		
		OntProperty hasSafe = oM.getOntProperty(uri + "has_safeguard");
		OntProperty rVl = oM.getOntProperty(uri + "risk_value");
		OntProperty pRV = oM.getOntProperty(uri + "potential_risk_value");
		List<QuerySolution> var = new ArrayList<QuerySolution>();
		List<String> individuos = new ArrayList<String>();
		List<String> risk = new ArrayList<String>();
		ResultSet select = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execSelect();
		
		for(;select.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = select.next();
	    	var.add(aux); 
	    }
		for(int i = 0; i < var.size(); i++) {
			String auxIn = oM.getIndividual(var.get(i).get("s").toString()).getURI();
			if(!individuos.contains(auxIn)) {
				individuos.add(auxIn);
			}
			for(int j = 0; j < individuos.size(); j++) {
				if(auxIn == individuos.get(j)) {
					String imp = var.get(i).get("i").toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
					String pro = var.get(i).get("p").toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
					float ris = Float.parseFloat(imp)*Float.parseFloat(pro);				
					if(!risk.isEmpty() && risk.size() == individuos.size()) {
						float ris2 = ris + Float.parseFloat(risk.get(j));
						risk.set(j, Float.toString(ris2));
					} else {
						risk.add(Float.toString(ris));
					}
				}
			}
		}

		for(int i = 0; i < individuos.size(); i++) {
			int n = 0;
			for(int j = 0; j < var.size(); j++) {
				if(oM.getIndividual(var.get(j).get("s").toString()).getURI() == individuos.get(i)) {
					n++;
				}
			}
			risk.set(i, Float.toString(Float.parseFloat(risk.get(i))/n));
		}

		for(int i = 0; i < individuos.size(); i++) {
			oM.getIndividual(individuos.get(i)).setPropertyValue(pRV, null);
			String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
					+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
		            "CONSTRUCT\n" + "{ <" + oM.getIndividual(individuos.get(i)).getURI() + "> Ontologia_TFG:potential_risk_value \"" + Float.parseFloat(risk.get(i)) + "\"^^xsd:float . " +
		            "   }\n" +
		            "WHERE\n" +
		            "  { <" + oM.getIndividual(individuos.get(i)).getURI() + "> a Ontologia_TFG:Risk .\n" +
		            "  }\n";
			
			Model construct = QueryExecutionFactory.create(QueryFactory.create(c3), oM).execConstruct();
		    oM.add(construct);
			if(!oM.getIndividual(individuos.get(i)).hasProperty(hasSafe)) {
				oM.getIndividual(individuos.get(i)).setPropertyValue(rVl, null);
				String c4 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
						+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
			            "CONSTRUCT\n" + "{ <" + oM.getIndividual(individuos.get(i)).getURI() + "> Ontologia_TFG:risk_value \"" + Float.parseFloat(risk.get(i)) + "\"^^xsd:float . " +
			            "   }\n" +
			            "WHERE\n" +
			            "  { <" + oM.getIndividual(individuos.get(i)).getURI() + "> a Ontologia_TFG:Risk .\n" +
			            "  }\n";
				
				Model construct2 = QueryExecutionFactory.create(QueryFactory.create(c4), oM).execConstruct();
			    oM.add(construct2);	
			}
		} 
		
		String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
				 "SELECT ?s ?p ?v \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Risk ."
		            + "?s Ontologia_TFG:has_safeguard ?o ."
		            + "?s Ontologia_TFG:potential_risk_value ?p ."
		            + " ?o Ontologia_TFG:safeguard_value ?v ." +
		            "  }\n";
		List<QuerySolution> var2 = new ArrayList<QuerySolution>();
        ResultSet select2 = QueryExecutionFactory.create(QueryFactory.create(c3), oM).execSelect();
		
		for(;select2.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = select2.next();
	    	var2.add(aux); 
	    }
		
		for(int i = 0; i < var2.size(); i++) {
			String auxIn = oM.getIndividual(var2.get(i).get("s").toString()).getURI();
			String pRv = var2.get(i).get("p").toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
			String saf = var2.get(i).get("v").toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
			float rv = Float.parseFloat(pRv) - Float.parseFloat(saf);
			oM.getIndividual(auxIn).setPropertyValue(rVl, null);
			String c4 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
					+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
		            "CONSTRUCT\n" + "{ <" + oM.getIndividual(auxIn).getURI() + "> Ontologia_TFG:risk_value \"" + rv + "\"^^xsd:float . " +
		            "   }\n" +
		            "WHERE\n" +
		            "  { <" + oM.getIndividual(auxIn).getURI() + "> a Ontologia_TFG:Risk .\n" +
		            "  }\n";
			Model construct2 = QueryExecutionFactory.create(QueryFactory.create(c4), oM).execConstruct();
		    oM.add(construct2);
		}
	}
	
	public void relationVul(String uri, String uri2, OntModel oM) {
		String c4 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	            "CONSTRUCT\n" + "{ ?a Ontologia2:has_vulnerability ?v . " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { ?a a Ontologia_TFG:Asset .\n" +
	           "  ?a Ontologia_TFG:info ?i .\n" +
	            "  ?v a Ontologia_TFG:Vulnerability .\n" +
	           "  ?v Ontologia_TFG:affect ?f .\n" +
	            "  FILTER(?i=?f)\n" +
	            "  }\n";
		Model construct = QueryExecutionFactory.create(QueryFactory.create(c4), oM).execConstruct();
	    oM.add(construct);
	}
	
	public void genVul(Individual asset, OntClass clVulTh, String dimin, String prob, String impa, String uri, String uri2, OntModel oM) {
	    Individual vulTh = oM.createIndividual(uri + "Threat_" + dimin, clVulTh);
	    String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	            "CONSTRUCT\n" + "{ <" + asset.getURI() + "> Ontologia2:isExposedTo <" + vulTh.getURI() + "> . " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { <" + asset.getURI() + "> a Ontologia_TFG:Asset .\n" +
	            "  }\n";
		
		Model construct = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execConstruct();
	    oM.add(construct);
	    OntProperty hv = oM.getOntProperty(uri2 + "has_vulnerability");
	    String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	            "CONSTRUCT\n" + "{ <" + oM.getIndividual(asset.getPropertyValue(hv).toString()).getURI() + "> Ontologia_TFG:exposesTo <" + vulTh.getURI() + "> . " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { <" + oM.getIndividual(asset.getPropertyValue(hv).toString()).getURI() + "> a Ontologia_TFG:Vulnerability .\n" +
	            "  }\n";
		
		Model construct2 = QueryExecutionFactory.create(QueryFactory.create(c3), oM).execConstruct();
	    oM.add(construct2);
	    instOf(clVulTh.getURI(), "Threat", oM);
	    genPaI(prob, impa, vulTh.getURI(), oM);
	}
	
	public void genAssetTh(Individual asset, OntClass clTh, String dimin, String prob, String impa, String uri, OntModel oM) {
	    Individual vulTh = oM.createIndividual(uri + "Threat_" + dimin, clTh);
	    String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	            "CONSTRUCT\n" + "{ <" + asset.getURI() + "> Ontologia2:isExposedTo <" + vulTh.getURI() + "> . " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { <" + asset.getURI() + "> a Ontologia_TFG:Asset .\n" +
	            "  }\n";
		
		Model construct = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execConstruct();
	    oM.add(construct);
	    instOf(clTh.getURI(), "Threat", oM);
	    genPaI(prob, impa, vulTh.getURI(), oM);
	}
	
	public void genPaI(String p, String i, String t, OntModel oM) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
	            "CONSTRUCT\n" + "{ <" + t + "> Ontologia_TFG:probability \"" + p + "\"^^xsd:float ; " +
	            "  Ontologia_TFG:impact \"" + i + "\"^^xsd:float " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { <" + t + "> a Ontologia_TFG:Threat .\n" +
	            "  }\n";
		
		Model construct = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execConstruct();
	    oM.add(construct);
	}
	
	public void instOf(String c, String g, OntModel oM) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
	            "CONSTRUCT\n" + "{ ?s a Ontologia_TFG:" + g + " . " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { ?s a <" + c + "> .\n" +
	            "  }\n";
		
		Model construct = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execConstruct();
	    oM.add(construct);
	}
	
	public void isGenBy(String i, String cl, OntModel oM) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	            "CONSTRUCT\n" + "{ <" + i + "> Ontologia2:isGeneratedBy ?o . " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { ?o a <" + cl + "> .\n" +	            
	            "  }\n";
		
		Model construct = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execConstruct();
	    oM.add(construct);
	}
	
	public void generates(String i, String cl, OntModel oM) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	            "CONSTRUCT\n" + "{ ?s Ontologia2:generates <" + i + "> . " +
	            "   }\n" +
	            "WHERE\n" +
	            "  { ?s a <" + cl + "> .\n" +	            
	            "  }\n";
		
		Model construct = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execConstruct();
	    oM.add(construct);
	}
	
	public float [] totalRisk(OntModel oM) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
				 "SELECT ?s ?o ?p \n" +
		            "WHERE\n" +
		            "  { ?s a Ontologia_TFG:Risk ." +
		            "?s Ontologia_TFG:risk_value ?o ." +
		            "?s Ontologia_TFG:potential_risk_value ?p .\n" +
		            "  }\n";
		List<QuerySolution> var = new ArrayList<QuerySolution>();
		ResultSet select = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execSelect();
		for(;select.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = select.next();
	    	var.add(aux); 
	    }
		float num = 0;
		float pNum = 0;
		for(int i = 0; i < var.size(); i++) {
			String risVal = var.get(i).get("o").toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
			String pRisVal = var.get(i).get("p").toString().replace("^^http://www.w3.org/2001/XMLSchema#float", "");
			num = num + Float.parseFloat(risVal);
			pNum = pNum + Float.parseFloat(pRisVal);
		}
		num = num/var.size();	
		pNum = pNum/var.size();
		OntProperty rValue = oM.getOntProperty("http://www.semanticweb.org/tfg/Ontologia_TFG#risk_value");
		OntProperty pRValue = oM.getOntProperty("http://www.semanticweb.org/tfg/Ontologia_TFG#potential_risk_value");
		Individual totalRiskI = oM.getIndividual("http://www.semanticweb.org/tfg/Ontologia_TFG#SystemTotalRisk"); 
		totalRiskI.setPropertyValue(pRValue, null);
		totalRiskI.setPropertyValue(rValue, null);
		if(num == num) {
			String c4 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
					+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
		            "CONSTRUCT\n" + "{ <" + totalRiskI.getURI() + "> Ontologia_TFG:risk_value \"" + num + "\"^^xsd:float ; " +
		             " Ontologia_TFG:potential_risk_value \"" + pNum + "\"^^xsd:float . " +
		            "   }\n" +
		            "WHERE\n" +
		            "  { <" + totalRiskI.getURI() + "> a Ontologia_TFG:TotalRisk .\n" +
		            "  }\n";
			Model construct2 = QueryExecutionFactory.create(QueryFactory.create(c4), oM).execConstruct();
		    oM.add(construct2); 
			System.out.println("TotalRisk: " + num);
			System.out.println("PotentialTotalRisk: " + pNum);
			float [] array = {pNum, num};
			return array;
		} else {
			String c4 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
					+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + "\n" +
		            "CONSTRUCT\n" + "{ <" + totalRiskI.getURI() + "> Ontologia_TFG:risk_value \"" + 0.0 + "\"^^xsd:float ; " +
		             " Ontologia_TFG:potential_risk_value \"" + 0.0 + "\"^^xsd:float . " +
		            "   }\n" +
		            "WHERE\n" +
		            "  { <" + totalRiskI.getURI() + "> a Ontologia_TFG:TotalRisk .\n" +
		            "  }\n";
			Model construct2 = QueryExecutionFactory.create(QueryFactory.create(c4), oM).execConstruct();
		    oM.add(construct2);
			System.out.println("TotalRisk: 0.0");
			System.out.println("PotentialTotalRisk: 0.0");
			float [] array = {0.0f, 0.0f};
			return array;
		}
	}
}
