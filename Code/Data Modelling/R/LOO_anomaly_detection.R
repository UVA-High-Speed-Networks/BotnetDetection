######################### Libraries ########################
library(plyr)
library(caret)
library(pROC)
library(tidyverse)
library(plotROC)
library(MASS)
library(car)
library(glmnet)
#Parallelization
library(parallel)
library(doParallel)
library(caret)

set.seed(11)

########################## Reading & Splitting Data ##############################
dir = '/Users/babraham/Google Drive/Grad_School/Cyber_Research/Anomaly-based-Intrusion-Detection-System/Code/Data Modelling/R'
all_data <- read.csv(paste(dir,'merged_data_final.csv',sep="/"), header=T) #reading in the data

#get rid of corrupted trace sample
all_data <- all_data[which(all_data$File != "traces_141_1.log.csv"),]

#get rid of index
all_data <- all_data[,-c(1)]

drop_cols <- c('srcIP','destIP','destPt','protocol','startTime','File','File.1','Type','Family')


########################## Log transform skewed columns ##############################
skewed_columns <- c('flowct','mean_dest_bytes','stdev_dest_bytes','mean_dest_pkts','stdev_dest_pkts','mean_duration',
                    'stdev_duration','mean_intvl','stdev_intvl','mean_src_pkts','stdev_src_pkts', 
                    'A','C','D','F','H','R','S','T','a','c','d','f','h','r','t')

########################## Summary statistics by bot family ##############################

malicious_traces <- all_data[all_data$Family!='Normal',]

all_data$Family  <- factor(all_data$Family , levels = c('Bunitu', 'Conflicker', 'Dridex', 'Miuref', 'Necurs', 'Trickbot', 'Upatre', 'Zeus', 'Normal'))

summary_flowct <- malicious_traces %>% group_by(Family) %>% summarise('Median (Flowcount)'= round(median(flowct),1), 'Std dev (Flowcount)' = round(sd(flowct),1), 
                                                              'Median (Mean Duration)'= round(median(mean_duration),1), 'Std dev (Mean Duration)' = round(sd(mean_duration),1),
                                                              'Median (Mean Source Packets)'= round(median(mean_src_pkts),1), 'Std dev (Mean Source Packets)' = round(sd(mean_src_pkts),1),
                                                              'Median (Mean intvl)'= round(median(mean_intvl),1), 'St dev (invl)' = round(sd(mean_intvl),1))
View(summary_flowct)

########################## Log transform skewed columns ##############################
#all_data[skewed_columns] <- sapply(all_data[skewed_columns], function(x) log(x+1))


########################## Create LOO function ##############################
create_LOO_datasets <- function(all_data, family_nm, thresh){  
  drop_cols <- c('srcIP','destIP','destPt','protocol','startTime','File','File.1','Type','Family')
  
  # Separate out normal traces from malicious traces
  normal_data <- all_data[all_data['Family']=='Normal',!(colnames(all_data) %in% drop_cols)]

  # Index for normal test data
  normal_test_index <- sample(1:nrow(normal_data),nrow(all_data[all_data['Family']==family_nm,]),replace = FALSE ) 
  
  # Create dataset with only malicious traces
  all_data2 <- all_data[all_data['Family']!='Normal',]
  
  # Remove traces of family_nm (LOO family) to create mal data
  mal_data <- all_data2[all_data2['Family']!=family_nm,!(colnames(all_data2) %in% drop_cols)]
  
  # Append train normal data to malicious data
  mal_data <- rbind(mal_data, normal_data[-normal_test_index,])
  
  # Create family mal data containing traces of LOO family
  family_mal_data <- all_data2[all_data2['Family']==family_nm,!(colnames(all_data2) %in% drop_cols)]
  
  # Append test normal data to LOO malicious data
  family_mal_data <- rbind(family_mal_data, normal_data[normal_test_index,])
  
  return(list(mal_data, family_mal_data))
}

########################## Create Logistic Regression function ##############################
# logistic_regr_LOO <- function(LOO_datasets, thresh){
#   mal_data <- LOO_datasets[[1]]
#   family_mal_data <- LOO_datasets[[2]]
#   
#   # Create train index for malicious dataset (all families other than LOO)
#   train_mal_index <- sample(1:nrow(mal_data), round(0.7*nrow(mal_data)), replace = FALSE)
#   
#   # Create test and train datasets
#   train_data <- as.matrix(mal_data[train_mal_index,])
#   test_data <- as.matrix(mal_data[-train_mal_index,])
#   
#   # train the model 
#   model <- cv.glmnet(train_data[,-c(1)],train_data[,'Malicious'], alpha = 1)
#   
#   lambda_1se <- model$lambda.1se
#   
#   probs <- predict(model,newx = test_data[,-c(1)],s=lambda_1se,type="response")
#   
#   preds <- rep(0,nrow(probs))
#   preds[probs>thresh] <- 1
#   
#   preds_table <- table(test_data[,'Malicious'], preds)
#   accuracy <- (preds_table[1,1] + preds_table[2,2]) / sum(preds_table)
#   
#   # Create final model with LOO as test and all other as train
#   final_model <- cv.glmnet(as.matrix(mal_data[,-c(1)]),as.matrix(mal_data[,'Malicious']), alpha = 1)
#   
#   final_lambda_lse <- final_model$lambda.1se
#   
#   probs <- predict(final_model,newx = as.matrix(family_mal_data[,-c(1)]),s=final_lambda_lse,type="response")
#   preds <- rep(0,nrow(probs))
#   preds[probs>thresh] <- 1
#   
#   # Create confusion matrix
#   cnfMatrix <- confusionMatrix(preds, as.factor(family_mal_data[,'Malicious']))
#   
#   # Calculate AUC values
#   roccurve <- pROC::roc(family_mal_data[,'Malicious'] ~ as.vector(probs))#
#   plot(roccurve)  
#   auc_value <- pROC::auc(roccurve)
#   plot(1-roccurve$specificities, roccurve$sensitivities)
#   # # Create ROC plots using ROCR package
#   # roc_pred <- ROCR::prediction( as.vector(probs), family_mal_data[,'Malicious'] )
#   # roc_perf <- ROCR::performance( roc_pred, "tpr", "fpr" )
#   # 
#   # Create ROC plots for Miuref and Bunitu
#   # if(family_nm=='Zeus'){
#   #   plot(roc_perf.predictions,roc_perf, col = "black", lty=3)
#   #   legend("topright", c(family_nm), lty=3,
#   #          col = "black", bty="n", inset=c(0,0.2))
# 
#   #}
#   # if(family_nm=='Bunitu'){
#   #   plot( roc_perf, add = TRUE, col= "black", lty=5)
#   #   legend("topright", c(family_nm), lty=5, 
#   #          col = "black", bty="n", inset=c(0,0.3))
#   #   
#   # } 
#   
#   return(list(cnfMatrix$byClass['Balanced Accuracy'][1],cnfMatrix$byClass['Precision'],
#               cnfMatrix$byClass['Recall'],cnfMatrix$byClass['F1'],
#               auc_value))
# }


########################## Perform Leave-One-Bot Out  ##############################
perform_LOO <- function(LOO_datasets, thresh, mtype="lr"){
  if(mtype == "nn"){mtype = "mlpML" }
  mal_data <- LOO_datasets[[1]]
  family_mal_data <- LOO_datasets[[2]]
  
  if(mtype == "lr"){
    # Apply log trnasform to skewed predictors
    #mal_data[skewed_columns] <- sapply(mal_data[skewed_columns], function(x) log(x+1))
    #family_mal_data[skewed_columns] <- sapply(family_mal_data[skewed_columns], function(x) log(x+1))
    
    # Create final model with LOO as test and all other as train
    final_model <- cv.glmnet(as.matrix(mal_data[,-c(1)]),as.matrix(mal_data[,'Malicious']), alpha = 1)
    final_lambda_lse <- final_model$lambda.1se
    print(final_model)
    
    #Evaluate model on LOO test data
    probs <- predict(final_model,newx = as.matrix(family_mal_data[,-c(1)]),s=final_lambda_lse,type="response")
    preds <- rep(0,nrow(probs))
    thresh = optimizeThresh(probs, family_mal_data$Malicious)
    print(paste("optimal threshold:",thresh, sep=" "))
    preds[probs>thresh] <- 1
  }
  else{ #use caret packet to train any other model type (rf, nb, svm,nn)
    mlp_grid = NULL
    preProc = c("center")
    
    if(mtype == "mlpML"){ #if nn, need to set up params for tuneGrid. Otherwise, set mlp_grid to empty variable
      num_vars = ncol(mal_data)-1
      mlp_grid = expand.grid(layer1 = c(10),
                             layer2 = c(5), 
                             layer3 = c(0))
      preProc <- c("range")
    }
    
    cluster <- makeCluster(detectCores())
    registerDoParallel(cluster)
    set.seed(234)
    control <- trainControl(method="cv", 
                            summaryFunction=twoClassSummary, classProbs=T,
                            savePredictions = T,allowParallel = TRUE)
    
    
    #train model
    if(mtype != "Ensemble"){
      lr <- cv.glmnet(as.matrix(mal_data[,-c(1)]),as.matrix(mal_data[,'Malicious']), alpha = 1)
      final_lambda_lse <- lr$lambda.1se
      print(final_model)
      #Convert response variable to factor for train and test datasets
      mal_data$Malicious <- as.factor(mal_data$Malicious)
      levels(mal_data$Malicious) <- c('Benign','Malicious')
      family_mal_data$Malicious <- as.factor(family_mal_data$Malicious)
      levels(family_mal_data$Malicious) <- c('Benign','Malicious')
      
      model <- train(x=mal_data[,-1], y=as.factor(mal_data[,'Malicious']), method = mtype,
                     trControl=control,
                     preProcess = preProc,
                     metric = "ROC",
                     tuneLength = 4,
                     tuneGrid = mlp_grid)
      print(model)
      probs <- predict(model,newdata = family_mal_data[,-c(1)], type="prob")
      probs <- probs$Malicious
      thresh <- optimizeThresh(probs, family_mal_data$Malicious)
    }else{#ensemble prediction with LR and RF
      lr <- cv.glmnet(as.matrix(mal_data[,-c(1)]),as.matrix(mal_data[,'Malicious']), alpha = 1)
      final_lambda_lse <- lr$lambda.1se
      print(lr)
      #Convert response variable to factor so caret train will work (not needed for LR)
      mal_data$Malicious <- as.factor(mal_data$Malicious)
      levels(mal_data$Malicious) <- c('Benign','Malicious')
      family_mal_data$Malicious <- as.factor(family_mal_data$Malicious)
      levels(family_mal_data$Malicious) <- c('Benign','Malicious')
      
      rf <- train(x=mal_data[,-1], y=as.factor(mal_data[,'Malicious']), method = "rf",
                  trControl=control,
                  preProcess = preProc,
                  metric = "ROC",
                  tuneLength = 4,
                  tuneGrid = mlp_grid)
      lr_probs <- predict(lr,newx = as.matrix(family_mal_data[,-c(1)]),s=final_lambda_lse,type="response")
      rf_probs <- predict(rf,newdata = family_mal_data[,-c(1)], type="prob")
      rf_probs <- rf_probs$Malicious
      params <- optimizeParams(lr_probs, family_mal_data[,'Malicious'], m2_probs = rf_probs)
      alph <- params[1]
      thresh <- params[2]
      print(paste('alpha: ',alpha, ', thresh: ', thresh, sep=""))
      probs <- alph * lr_probs + (1-alph)*rf_probs
    }
    
    #Calculate accuracy based on thresholded probabilities
    preds <- rep(0,length(probs))
    preds[probs>thresh] <- 1
    preds <- as.factor(preds)
    levels(preds) <- c('Benign', 'Malicious')
    lr_preds <- rep(0,length(probs))
    lr_preds[lr_probs>thresh] <- 1
    lr_preds <- as.factor(lr_preds)
    levels(lr_preds) <- c('Benign', 'Malicious')
    
    preds_table <- table(family_mal_data[,'Malicious'], preds)
    accuracy <- (preds_table[1,1] + preds_table[2,2]) / sum(preds_table)
  }
  
  # Create confusion matrix
  cnfMatrix <- confusionMatrix(preds, family_mal_data[,'Malicious'])
  # Calculate AUC values
  roccurve <- pROC::roc(family_mal_data[,'Malicious'] ~ as.vector(probs))#
  #plot(roccurve)  
  auc_value <- pROC::auc(roccurve)
  
  return(list(cnfMatrix$byClass['Balanced Accuracy'][1],cnfMatrix$byClass['Precision'],
              cnfMatrix$byClass['Recall'],cnfMatrix$byClass['F1'],
              auc_value, probs, family_mal_data[,'Malicious'],data.frame(cbind(preds,family_mal_data[,'Malicious'])))) 
}

########################## Hyper-parameter Tuning ##########################
optimizeParams = function(probs, labels, stepsize=.005, m2_probs=NULL){
  threshCount = 1 / stepsize
  threshlist =  seq(1,threshCount) * stepsize
  if(!is.null(m2_probs)){
    num_alpha = 10
    alphas = seq(1,num_alpha) / num_alpha
    paramList = list()
    perfs = c()
    idx=1
    for(i in c(1:length(alphas))){
      for(j in c(1:length(threshlist))){
        alpha = alphas[[i]]
        thresh = threshlist[[j]]
        comb_probs <- alpha * probs + (1-alpha) * m2_probs
        preds <- rep(0,length(comb_probs))
        preds[comb_probs>thresh] <- 1
        preds <- as.factor(preds)
        levels(preds) <- c('Benign', 'Malicious')
        cnfMatrix <- confusionMatrix(preds, labels)
        perfs <- c(perfs, cnfMatrix$byClass['F1'][[1]])
        paramList[[idx]] <- c(alpha,thresh)
        idx <- idx + 1
      }
    }
  }
  else{
    paramList = threshlist
    #perfs = vector(mode="list", length = threshCount)
    perfs = c()
    for(i in c(1:threshCount)){
      preds <- rep(0,length(probs))
      preds[probs>paramList[[i]]] <- 1
      preds <- as.factor(preds)
      levels(preds) <- c('Benign', 'Malicious')
      cnfMatrix <- confusionMatrix(preds, labels)
      perfs <- c(perfs,cnfMatrix$byClass['F1'][[1]])
    }
  }
  maxInd = which.max(perfs)
  return(paramList[[maxInd]])
}

########################## Implement Leave-One-Out ##############################

# For logistic regreeion, set custom threshold for each family
family_thresh <- c(0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5)
names(family_thresh) <- c('Miuref','Bunitu','Upatre','Dridex','Necurs','Trickbot','Conflicker','Zeus')

family_thresh <- family_thresh[5:length(family_thresh)]
# Create empty dataframe loo_df
loo_df <- data.frame(family = character(), balanced_accuracy = integer(), precision = integer(), recall = integer(), F1Score = integer(), auc = integer())

# Iterate through all botnet families one by one and implement Leave-One-Out
for(family_nm in names(family_thresh)){
  loo_datasets <- create_LOO_datasets(all_data = all_data,family_nm = family_nm, thresh=0.5)
  #loo_outcome <- logistic_regr_LOO(loo_datasets, thresh = family_thresh[family_nm])
  loo_outcome <- perform_LOO(loo_datasets, thresh = family_thresh[family_nm], mtype="Ensemble")
  loo_df <- rbind(loo_df, data.frame(family = family_nm, balanced_accuracy = unlist(loo_outcome)[[1]],
                                     precision = unlist(loo_outcome)[[2]] , recall= unlist(loo_outcome)[[3]],
                                     F1Score = unlist(loo_outcome)[[4]], auc = unlist(loo_outcome)[[5]]))
}

print(loo_df)

#Ensemble (LR and RF)
# family balanced_accuracy precision    recall   F1Score       auc
# 1     Miuref         0.9956204 0.9985316 0.9927007 0.9956076 0.9994587
# 2     Bunitu         0.8973496 0.8652549 0.9412844 0.9016698 0.9726613
# 3     Upatre         0.9954955 0.9910714 1.0000000 0.9955157 0.9995942
# 4     Dridex         1.0000000 1.0000000 1.0000000 1.0000000 1.0000000
# 5     Necurs         0.9986034 0.9972145 1.0000000 0.9986053 0.9999827
# 6   Trickbot         0.9952830 1.0000000 0.9905660 0.9952607 0.9998220
# 7 Conflicker         1.0000000 1.0000000 1.0000000 1.0000000 1.0000000
# 8       Zeus         0.9453718 0.9104895 0.9878604 0.9475983 0.9856038

#Random Forest
# family balanced_accuracy precision    recall   F1Score       auc
# 1     Miuref         0.9934307 0.9985251 0.9883212 0.9933969 0.9997568
# 2     Bunitu         0.7726809 0.6880360 0.9977574 0.8144450 0.9540091
# 3     Upatre         0.9954955 0.9910714 1.0000000 0.9955157 0.9994319
# 4     Dridex         1.0000000 1.0000000 1.0000000 1.0000000 1.0000000
# 5     Necurs         0.9944134 1.0000000 0.9888268 0.9943820 0.9999809
# 6   Trickbot         0.9976415 1.0000000 0.9952830 0.9976359 0.9997998
# 7 Conflicker         0.9958333 1.0000000 0.9916667 0.9958159 1.0000000
# 8       Zeus         0.5318665 0.5166403 0.9893778 0.6788131 0.9250313


#Logistic Regression - Pre Log Transform
# family balanced_accuracy precision    recall   F1Score       auc
# 1     Miuref         0.8605839 1.0000000 0.7211679 0.8379983 0.9322937
# 2     Bunitu         0.8438328 1.0000000 0.6876656 0.8149311 0.9057309
# 3     Upatre         0.9369369 0.9075630 0.9729730 0.9391304 0.9835241
# 4     Dridex         0.8135593 0.7341772 0.9830508 0.8405797 0.9485780
# 5     Necurs         0.8510242 1.0000000 0.7020484 0.8249453 0.9124260
# 6   Trickbot         0.8466981 1.0000000 0.6933962 0.8189415 0.9333615
# 7 Conflicker         0.8406250 1.0000000 0.6812500 0.8104089 0.9078385
# 8       Zeus         0.9484067 0.9087137 0.9969651 0.9507959 0.9846240


#Logistic Regression - Post Log Transform
# family balanced_accuracy precision    recall   F1Score       auc
# 1     Miuref         0.9463504 0.9729312 0.9182482 0.9447991 0.9715312
# 2     Bunitu         0.8414883 0.7979367 0.9145770 0.8522846 0.9228054
# 3     Upatre         0.9684685 0.9561404 0.9819820 0.9688889 0.9909098
# 4     Dridex         0.9830508 1.0000000 0.9661017 0.9827586 0.9974145
# 5     Necurs         0.9972067 0.9981343 0.9962756 0.9972041 0.9982158
# 6   Trickbot         0.9740566 0.9631336 0.9858491 0.9743590 0.9949493
# 7 Conflicker         0.9687500 0.9629630 0.9750000 0.9689441 0.9815495
# 8       Zeus         0.5030349 0.5015244 0.9984825 0.6676814 0.6563400

#Logistic Regression - OG results
# family balanced_accuracy precision    recall   F1Score       auc
# 1     Miuref         0.8748175 0.8187461 0.9627737 0.8849379 0.9776413
# 2     Bunitu         0.6972477 0.6244053 0.9900102 0.7658098 0.9211530
# 3     Upatre         0.9729730 0.9816514 0.9639640 0.9727273 0.9918026
# 4     Dridex         0.9661017 0.9661017 0.9661017 0.9661017 0.9959782
# 5     Necurs         0.9799814 0.9990319 0.9608939 0.9795918 0.9989441
# 6   Trickbot         0.9716981 0.9761905 0.9669811 0.9715640 0.9934585
# 7 Conflicker         0.9625000 0.9605809 0.9645833 0.9625780 0.9803646
# 8       Zeus         0.4946889 0.4972635 0.9650986 0.6563467 0.7209687


#Neural Net
# family balanced_accuracy precision    recall   F1Score       auc
# 1     Miuref         0.8291971 0.9966960 0.6605839 0.7945566 0.9351833
# 2     Bunitu         0.5919470 0.5511686 0.9904179 0.7082149 0.9061623
# 3     Upatre         0.9504505 0.9098361 1.0000000 0.9527897 0.9919649
# 4     Dridex         0.8305085 0.9148936 0.7288136 0.8113208 0.8983051
# 5     Necurs         0.8445065 0.9986523 0.6899441 0.8160793 0.9440951
# 6   Trickbot         0.8561321 1.0000000 0.7122642 0.8319559 0.9594607
# 7 Conflicker         0.8156250 0.9577039 0.6604167 0.7817509 0.9558247
# 8       Zeus         0.8338392 1.0000000 0.6676783 0.8007279 0.9892351

#################### Implement logistic regression for entire dataset #######################


# Create all_data2 by removing unnecessary columns
all_data2 <- all_data[,!(colnames(all_data) %in% drop_cols)]

# Select only those rows with are not null
all_data2 <- all_data2[complete.cases(all_data2),]

#Apply log transforms to skewed columns
all_data2[skewed_columns] <- sapply(all_data2[skewed_columns], function(x) log(x+1))

# Create train test for entire dataset
train_index <- sample(1:nrow(all_data2), round(0.7*nrow(all_data2)), replace = FALSE)
full_train <- all_data2[train_index,]
full_test <- all_data2[-train_index,]


final_model <- cv.glmnet(as.matrix(full_train[,-c(1)]),as.matrix(full_train[,'Malicious']), alpha = 1)
final_lambda_lse <- final_model$lambda.1se

probs <- predict(final_model,newx = as.matrix(full_test[,-c(1)]),s=final_lambda_lse,type="response")

roccurve <- pROC::roc(full_test[,'Malicious'] ~ as.vector(probs))
plot(roccurve)  
auc_value <- pROC::auc(roccurve)

thresh <- 0.45
preds <- rep(0,nrow(probs))
preds[probs>thresh] <- 1

cnfMatrix <- confusionMatrix(preds, as.factor(full_test[,'Malicious']))
cnfMatrix$byClass['Balanced Accuracy'][1]
cnfMatrix$byClass['Precision']
cnfMatrix$byClass['Recall']
cnfMatrix$byClass['F1']



#Zeus test
zeus <- all_data[which(all_data$Family == "Zeus"),]
normal <- all_data[which(all_data$Family == "Normal"),]
normal_inds <- sample(1:nrow(normal),nrow(all_data[all_data['Family']=="Zeus",]),replace = FALSE ) 
zeus_all = data.frame(rbind(zeus,normal[normal_inds,]))
zeus_all <- zeus_all[,!(colnames(zeus_all) %in% drop_cols)]
zeus_all$Malicious <- as.factor(zeus_all$Malicious)
levels(zeus_all$Malicious) <- c('Benign', 'Malicious')
#Mod  F1
#LR   .963


##############pre-log training/results########################
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)
loo_datasets <- create_LOO_datasets(all_data, 'Zeus')
mal_data <- loo_datasets[[1]]
family_mal_data <- loo_datasets[[2]]
lr <- cv.glmnet(as.matrix(mal_data[,-c(1)]),as.matrix(mal_data[,'Malicious']), alpha = 1)
final_lambda_lse <- lr$lambda.1se
lr_probs <- predict(lr,newx = as.matrix(family_mal_data[,-c(1)]),s=final_lambda_lse,type="response")

rf1 <- randomForest(mal_data[,-c(1)],mal_data[,1], mtry = 11, ntree = 300, importance = T)
rf_probs <- predict(rf,newdata = family_mal_data[,-c(1)], type="prob")
rf_probs <- rf_probs$Malicious
dim(family_mal_data)

#train rf on zeus data without any preprocessing
rf <- train(as.factor(Malicious) ~., data = zeus_all, method = "rf",
            trControl=control,
            metric = "ROC",
            tuneLength = 4)
print(rf) #best model: 11    0.9998393  0.9893939  0.9984848
# variable importance plot
rf1 <- randomForest(zeus_all[,-c(1)], zeus_all[,1], mtry = 11, ntree = 300, importance = T)
var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")

zeus_summary <- zeus_all %>% group_by(Malicious) %>% summarise('avg_mean_intvl' = mean(mean_intvl), 'avg_st_intvl' = mean(stdev_intvl),
                                                               'avg_mean_src_pkts' = mean(mean_src_pkts), 'avg_st_src_pkts' = mean(stdev_src_pkts),
                                                               'avg_F' = mean(F))
View(zeus_summary)

#boxplots for most important features
metrics = c("mean_intvl", "stdev_intvl", "H", "mean_src_pkts", "stdev_src_pkts",  "t")
plots <- list()
idx = 1
for(m in metrics){
  print(m)
  pdata = zeus_all[which(zeus_all[,c(m)] < quantile(zeus_all[,m], probs=c(.9))),]
  plots[[idx]] = ggplot(data = pdata,aes_string(x= "Malicious", y= m, fill = "Malicious")) + geom_boxplot()+
    scale_fill_manual(values=c("green", "red"))+
    theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
          axis.title=element_text(size=20,face="bold",color = "grey19"))
  idx = idx + 1
}
grid.arrange(plots[[1]], plots[[2]], plots[[3]], plots[[4]], plots[[5]], plots[[6]], ncol=2)

##############post-log transforms training/results########################

#train rf on zeus data without any preprocessing
rf_log <- train(as.factor(Malicious) ~., data = zeus_all, method = "rf",
            trControl=control,
            metric = "ROC",
            tuneLength = 4)
print(rf_log)   #best model: 2    0.9957334  0.9802564  0.9741958

# variable importance plot
rf2 <- randomForest(zeus_all[,-c(1)], zeus_all[,1], mtry = 11, ntree = 300, importance = T)
var_imp2 <- varImpPlot(rf2, sort = TRUE, main = "Variable Importance")

zeus_summary <- zeus_all %>% group_by(Malicious) %>% summarise('avg_mean_intvl' = mean(mean_intvl), 'avg_st_intvl' = mean(stdev_intvl),
                                                               'avg_mean_src_pkts' = mean(mean_src_pkts), 'avg_st_src_pkts' = mean(stdev_src_pkts),
                                                               'avg_F' = mean(F))
View(zeus_summary)

#apply log transform to all skewed columns
zeus_all[skewed_columns] <- sapply(zeus_all[skewed_columns], function(x) log(x+1))

metrics = c("mean_intvl", "stdev_intvl", "H", "mean_src_pkts", "stdev_src_pkts",  "t")
plots_log <- list()
idx = 1
for(m in metrics){
  print(m)
  pdata = zeus_all[which(zeus_all[,c(m)] < quantile(zeus_all[,m], probs=c(.9))),]
  plots_log[[idx]] = ggplot(data = pdata,aes_string(x= "Malicious", y= m, fill = "Malicious")) + geom_boxplot()+
    scale_fill_manual(values=c("green", "red"))+
    theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
          axis.title=element_text(size=20,face="bold",color = "grey19"))
  idx = idx + 1
}
grid.arrange(plots_log[[1]], plots_log[[2]], plots_log[[3]], plots_log[[4]], plots_log[[5]], plots_log[[6]], ncol=2)

#apply k-means clustering to all malicious traffic - first, find optimal # of clusters.
clustering_data <- all_data[all_data['Family']!='Normal',!(colnames(all_data) %in% drop_cols)]
#remove flags
clustering_data <- clustering_data[,c(2:12)]
wss <- (nrow(clustering_data)-1)*sum(apply(clustering_data,2,var))
for (i in 2:15) wss[i] <- sum(kmeans(clustering_data,
                                     centers=i)$withinss)
plot(1:15, wss, type="b", xlab="Number of Clusters",
     ylab="Within groups sum of squares")

#best k values: 3 and 9 (but the latter is simply the # of bot families...)

#perform pca on malicious data
pc <- prcomp(clustering_data)
# First for principal components
comp <- data.frame(pc$x[,1:4])
# Plot
plot(comp, pch=16, col=rgb(0,0,0,0.5))

#apply K-means with optimal # of clusters to principal components
k <- kmeans(comp, 3, nstart=25, iter.max=1000)
library(RColorBrewer)
library(scales)
palette(alpha(brewer.pal(9,'Set1'), 0.5))
plot(comp, col=k$clust, pch=16)

clustering_comb <- data.frame(cbind(clustering_data, comp, k$cluster))

##########logstic regression with and without transform for Zeus (LOO)###################
loo_datasets <- create_LOO_datasets(all_data=all_data, family_nm="Zeus", 0.5)
res = logistic_regr_LOO(loo_datasets, 0.5)


cnfMatrix$byClass['F1']

#############Variable importance plot for RF trianed on all data##########
all_data$Malicious <- as.factor(all_data$Malicious)
levels(all_data$Malicious) <- c("Benign", "Malicious")
#Remove t,f, and a flags
drop_cols <- c(drop_cols, "t", "T", "f", "F", "a", "A")
rf_data <- all_data[,!(colnames(all_data) %in% drop_cols)]
rf1 <- randomForest::randomForest(rf_data[,-c(1)],rf_data$Malicious, mtry=11,  ntree = 300, importance = T)
var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")
imp <- data.frame((rf1$importance)[,3])

imp <- imp %>% rownames_to_column(var="Variables") %>% remove_rownames
colnames(imp)[2] <-  "MeanAccuracyDecrease"
imp <- imp[order(-imp$MeanAccuracyDecrease),][2:25,]


varImpPlot <- ggplot(imp) + geom_point(aes(x = MeanAccuracyDecrease,y = reorder(Variables, MeanAccuracyDecrease)), size = 5, color = "sienna2")+
  ylab("Variables") + 
  theme(panel.background = element_rect(fill = 'grey93'),
        axis.text=element_text(size=12, face = "bold",color = "grey18"),
        axis.title=element_text(size=20,face="bold",color = "grey18"),
        plot.background = element_rect(fill = "grey93"))

##############LOBO (Bunitu) for all algorithms################
all_data_loo <- all_data[,!colnames(all_data) %in% drop_cols]
all_data_loo$Family <- all_data$Family
loo_datasets <- create_LOO_datasets(all_data=all_data_loo, family_nm="Bunitu", 0.5)
#LR
lr_outcome <- perform_LOO(loo_datasets, thresh = .5, mtype="lr")
lambda_1se <- 0.0007591463
#NB
nb_loo_datasets <- loo_datasets
nb_dropcols <- c("C","I","Q","T","c","i","q","s","t")
nb_loo_datasets[[1]] <- nb_loo_datasets[[1]][,!colnames(nb_loo_datasets[[1]]) %in% nb_dropcols]
nb_loo_datasets[[2]] <- nb_loo_datasets[[2]][,!colnames(nb_loo_datasets[[2]]) %in% nb_dropcols]
nb_outcome <- perform_LOO(nb_loo_datasets, thresh = .5, mtype="nb")
#final model: fl=0, usekernel=FALSE, adjust=1
#RF
rf_outcome <- perform_LOO(loo_datasets, thresh = .5, mtype="rf")
#mtry: 11
#SVM
svm_outcome <- perform_LOO(loo_datasets, thresh = .5, mtype="svmRadial")
#ANN
ann_outcome <- perform_LOO(loo_datasets, thresh = .5, mtype="nn")

rf_preds <- rf_outcome[[6]]
svm_preds <- svm_outcome[[6]]
nb_preds <- nb_outcome[[6]]
ann_preds <- ann_outcome[[6]]
lr_preds <- lr_outcome[[6]]


all_preds <- data.frame(cbind(rf_preds,svm_preds,nb_preds,ann_preds,lr_preds))
colnames(all_preds) <- c("Random_Forest", "Radial_SVM", "Naive_Bayes", "Neural_Net", "Logistic_Regression")
all_preds$Label <-rf_outcome[[7]]
#levels(all_preds$Label) <- c("Benign", "Malicious")
#Merge probabilities
all_preds <- Reduce(function(dtf1, dtf2) merge(dtf1, dtf2, by = c("obs", "rowIndex"), all = TRUE),list(rf_no_preds,svm_no_preds, nb_no_preds, lr_no_preds, nn_no_preds))
all_preds_sub <- all_preds[which(!is.na(all_preds$`Radial SVM`)),]
########### With Naive Bayes ###################
#Melt into longform for vizualization
longtest <- melt_roc(all_preds, "Label", m=c("Random_Forest", "Radial_SVM", "Naive_Bayes", "Neural_Net", "Logistic_Regression"))

#Plot
combined_roc <- ggplot(longtest, aes(d = D, m = M, color = name )) + geom_roc(n.cuts = F, size = 1)

plot4 <- combined_roc+
  theme(axis.text=element_text(size=12,color = "grey18"),
        axis.title=element_text(size=20,color = "grey18"),
        legend.text = element_text(size=16),
        legend.title = element_text(size=18),
        plot.background = element_rect(fill = "white"), 
        panel.background = element_rect(fill = "grey97"),
        panel.grid.major = element_line(color="grey77"),
        panel.grid.minor = element_line(color="grey77"),
  )+
  labs(x="False Positive Rate", y="True Positive Rate", color="Model")
