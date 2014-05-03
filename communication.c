#include "communication.h"





void set_up_comm(int dm, int usr) {
  printf("[ setup communication ] \n");
  DM_num = 0;
  dms = (domain_manager* ) malloc(sizeof(domain_manager)* dm);
  user_num = 0;
  users = (user* ) malloc(sizeof(user)* usr);
  char param[1024];
  size_t count = fread(param, 1, 1024, stdin);
  if (!count) pbc_die("input error");
  pairing_init_set_buf(pairing, param, count);
}

void set_up_domain_manager(domain_manager* who, public_key parent) {
  // printf("[ SETUP_DM ");
  if (parent.level == 0) {
    printf(" if %s ]\n", who->name);
    public_key temp = init_public_key(&parent);
    who->pk.ID_tuple = temp.ID_tuple;
    who->pk.level = temp.level;
    who -> MK =  create_DM(ROOT.MK, who->pk, *(ROOT.param));
    param_copy_PP(&(who->param), ROOT.param);    
  }
  else{
    // printf(" else  %s ]\n", who->name);
    domain_manager x;
    domain_manager* y = dm_from_publickey(parent);
    public_key temp1 = init_public_key(&parent);
    who->pk.ID_tuple = temp1.ID_tuple;
    who->pk.level = temp1.level;
    //x.MK
    who->MK= create_DM(y->MK, who->pk, *(ROOT.param) );
    //who->MK = x.MK;
    param_copy_PP(&(who->param),ROOT.param);
    //updateparentchildren
    
    public_key* temp = (public_key* ) malloc(sizeof(public_key) * (y->number_of_children + 1) );
    int i;
    for (i = 0; i < y->number_of_children; ++i) {
      public_key_copy(temp + i, y->children_dm  + i);
    }
    y->children_dm += 1;
    public_key_copy(temp + i, &(who->pk));

    
    for(i = 0; i < y->number_of_children  - 1; ++i) {
      free_public_key(y->children_dm  + i);
    }
    
    y->children_dm = temp;
    
  }
}

/* void set_up_user(user* user, public_key parent_pk)  { */
/* 	domain_manager* parent_dm = dm_from_publickey(parent_pk); */
/* 	public_key pk_u = init_public_key(&parent_dm); */
/* 	user->pk = pk_u; */
/* 	create_user_returntype rt = create_user(parent_dm->MK, pk_u,  */
/* } */

int get_next_id(public_key* parent) {
  if(parent->level == 0) {
    return ROOT.number_of_dm++;
  }
  domain_manager* par = dm_from_publickey(*parent);
  int ret = par->id;
  par->id += 1;
  return ret;
}

domain_manager* dm_from_publickey(public_key pk) {
  int i;
  for(i = 0; i < DM_num; ++i) {
    if( pkcomp(pk, dms[i].pk)) {
      return dms + i;
    }
  }
  return NULL;
}

int pkcomp(public_key a, public_key b) {
  int i;
  if(a.level != b.level) {
    return 0;
  }
  for(i = 0; i <= a.level; ++i) {
    if(a.ID_tuple[i] != b.ID_tuple[i]) {
      return 0;
    }
  }
  return 1;
}

void get_params(params** dest) {
  param_copy_PP(dest, ROOT.param);
}

// just in user_add_attribute useable
void  add_attribute( user_secret_key * out, public_key pk, public_key att) {
  //trick it s just a fake public_key
  public_key par_pk;
  par_pk.ID_tuple = att.ID_tuple;
  par_pk.level = att.level - 1;
  public_key_copy(&(out->pk), &par_pk);
  domain_manager* par = dm_from_publickey(par_pk);
  Q_tuple SK_u;
  generate_SK_u(&SK_u,par, pk);
  //	free_Q_tuple(out->Q_tuple);
  element_t SK_a;
  generate_SK_ua(&SK_a, par, pk, att);
  out-> SK_a = (element_t* ) malloc( sizeof(element_t));
  out->number_of_attributes = 1;
  element_init_G1(out->SK_a[0], pairing);
  element_set(out->SK_a[0], SK_a);
  element_clear(SK_a);
  out->Q_tuple = SK_u;
  attribute temp;
  attribute_from_pk(&temp, att);
  out->attribute = (attribute*) malloc(sizeof(attribute));
  attribute_copy(out->attribute, &temp);
  free_attribute(temp);
}

void attribute_from_pk (attribute* att, public_key pk ) {
  public_key dm_pk;
  dm_pk.ID_tuple = pk.ID_tuple;
  dm_pk.level = pk.level - 1;
  domain_manager* dm = dm_from_publickey(dm_pk);
  if(dm == NULL) {
    att->name = NULL;
    att->DM.ID_tuple = NULL;
    att->DM.level = 0;
  }
  int i;
  for(i = 0; i < dm->number_of_attributes; ++i) {
    if(pkcomp(dm->attributes[i].DM, pk)) {
      attribute_copy(att, dm->attributes + i);
    }
  }
}


void ask_elementsum(element_t* dest, conjuctive_clouse cc ) {
  public_key pk;
  pk.level = cc.attributes[0].DM.level - 1;
  pk.ID_tuple = cc.attributes[0].DM.ID_tuple;
  domain_manager* dm = dm_from_publickey(pk);
  elementsum(dm, dest, cc);
}


void add_to_db(attribute_db* db, attribute* att) {
  int i;
  attribute* temp  = (attribute* ) malloc(sizeof(attribute) * (db->db + 1));
  for (i = 0; i < db->db; ++i) {
    attribute_copy(temp + i, db->attributes + i);
  }
  attribute_copy(temp + i, att);
  free(db->attributes);
  db->attributes = temp;
  db->db += 1;
}
