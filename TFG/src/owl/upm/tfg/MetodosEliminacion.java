package owl.upm.tfg;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.jena.ontology.Individual;
import org.apache.jena.ontology.OntModel;
import org.apache.jena.ontology.OntProperty;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;

public class MetodosEliminacion {
	public void eliminate(OntModel oM, int limit, String uri) throws ParseException {
	  
	    String an = ""; //individuos de anomalia
	    String dat = ""; //fecha de su creación
	    String th = ""; //individuos amenaza
		Date fechaHoy= new Date(); //fecha actual	
		
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd"); //formato de fechas que deben tener los individuos de anomalias tambien
		
		String prefix = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
	            "SELECT ?s ?o ?x \n" +
	            "WHERE\n" +
	            "  { ?s a Ontologia_TFG:Detected_Anomaly ."
	            + "?s Ontologia_TFG:date ?o .\n" +
	              "?x Ontologia2:isGeneratedBy ?s .\n" +
	            "  }\n"; //la clase debe ser la genral que englobe a todas las anomalias
		
		Query query = QueryFactory.create(prefix); // query de sparql anterior
		
		ResultSet results = QueryExecutionFactory.create(query, oM).execSelect(); //resultado de ejecucion de la query
		
		List<QuerySolution> var =new ArrayList<QuerySolution>(); //lista ara guardar resultados de la query
		
	    for(;results.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = results.next();
	    	var.add(aux); //se guardan los resultados
	    }
	    
	    for(int i = 0; i < var.size(); i++) {
	    	an = var.get(i).get("s").toString();
	        dat = var.get(i).get("o").toString();
	        th = var.get(i).get("x").toString(); //se convierten a string los distintos parametros: anomalias, fechas y amenazas
	        OntProperty risVal = oM.getOntProperty(uri + "risk_value");
	        OntProperty pRisVal = oM.getOntProperty(uri + "potential_risk_value");
	        
	        Date fechaBase;
	        fechaBase = dateFormat.parse(dat);
	        
	    	int dias=(int) ((fechaHoy.getTime()-fechaBase.getTime())/86400000);//se hace la diferencia de dias
	    	
	    	if (dias > limit) {
	    		oM.getIndividual(oM.getIndividual(th).getOntClass(true).getURI() + "Risk_Risk").setPropertyValue(risVal, null);
	    		oM.getIndividual(oM.getIndividual(th).getOntClass(true).getURI() + "Risk_Risk").setPropertyValue(pRisVal, null);
	    		oM.getIndividual(th).remove();
	    		oM.getIndividual(an).remove(); //se borran las anomalias con sus respectivas amenazas		
	    	} else {
	    	}
	    }
	}
	
	public void changeAsset(OntModel oM) {
		String c2 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
				+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
				"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
				 "SELECT ?a ?v ?i ?f \n" +
		            "WHERE\n" +
		            "  { ?a Ontologia2:has_vulnerability ?v ."
		            + "?a Ontologia_TFG:info ?i ." +
		            "?v Ontologia_TFG:affect ?f ." +
		            "  }\n";
		List<QuerySolution> var = new ArrayList<QuerySolution>();
        ResultSet select = QueryExecutionFactory.create(QueryFactory.create(c2), oM).execSelect();
        for(;select.hasNext();) {	
	    	QuerySolution aux = null;   	
	    	aux = select.next();
	    	var.add(aux); 
	    }
        
        OntProperty hv = oM.getOntProperty("http://www.co-ode.org/ontologies/ont.owl#has_vulnerability");
        for(int i = 0; i < var.size(); i++) {
        	String asset = var.get(i).get("a").toString();
        	String vul = var.get(i).get("v").toString();
			String info = var.get(i).get("i").toString();
			String affect = var.get(i).get("f").toString();
			if(!info.equals(affect)) {
				oM.getIndividual(asset).setPropertyValue(hv, null);
				String c3 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
						+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
						"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
						 "SELECT ?t \n" +
				            "WHERE\n" +
				            "  { <" + asset + "> Ontologia2:isExposedTo ?t ." +
				            "  }\n";
				String c4 = "PREFIX Ontologia_TFG: <http://www.semanticweb.org/tfg/Ontologia_TFG#>\n"
						+ "PREFIX xsd:<http://www.w3.org/2001/XMLSchema#>\n" + 
						"PREFIX Ontologia2: <http://www.co-ode.org/ontologies/ont.owl#>" + "\n" +
						 "SELECT ?t \n" +
				            "WHERE\n" +
				            "  { <" + vul + "> Ontologia_TFG:exposesTo ?t ." +
				            "  }\n";
				
				List<QuerySolution> var1 = new ArrayList<QuerySolution>();
				List<QuerySolution> var2 = new ArrayList<QuerySolution>();
		        ResultSet select1 = QueryExecutionFactory.create(QueryFactory.create(c3), oM).execSelect();
		        ResultSet select2 = QueryExecutionFactory.create(QueryFactory.create(c4), oM).execSelect();
		        
		        for(;select1.hasNext();) {	
			    	QuerySolution aux = null;   	
			    	aux = select1.next();
			    	var1.add(aux); 
			    }
		        
		        for(;select2.hasNext();) {	
			    	QuerySolution aux = null;   	
			    	aux = select2.next();
			    	var2.add(aux); 
			    }
		        
		        for(QuerySolution t1: var1) {
		        	String ameAsset = t1.get("t").toString();
		        	for(QuerySolution t2: var2) {
			        	String ameVul = t2.get("t").toString();
			        	if(ameAsset.equals(ameVul)) {
							oM.getIndividual(ameVul).remove();
			        	}
			        }
		        }
			}
		}
	}
}
