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
                                                              'Median (Mean Source Packets)'= round(median(mean_src_pkts),1), 'Std dev (Mean Source Packets)' = round(sd(mean_src_pkts),1))
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
logistic_regr_LOO <- function(LOO_datasets, thresh){
  mal_data <- LOO_datasets[[1]]
  family_mal_data <- LOO_datasets[[2]]
  
  # Create train index for malicious dataset (all families other than LOO)
  train_mal_index <- sample(1:nrow(mal_data), round(0.7*nrow(mal_data)), replace = FALSE)
  
  # Create test and train datasets
  train_data <- as.matrix(mal_data[train_mal_index,])
  test_data <- as.matrix(mal_data[-train_mal_index,])
  
  # train the model 
  model <- cv.glmnet(train_data[,-c(1)],train_data[,'Malicious'], alpha = 1)
  
  lambda_1se <- model$lambda.1se
  
  probs <- predict(model,newx = test_data[,-c(1)],s=lambda_1se,type="response")
  
  preds <- rep(0,nrow(probs))
  preds[probs>thresh] <- 1
  
  preds_table <- table(test_data[,'Malicious'], preds)
  accuracy <- (preds_table[1,1] + preds_table[2,2]) / sum(preds_table)
  
  # Create final model with LOO as test and all other as train
  final_model <- cv.glmnet(as.matrix(mal_data[,-c(1)]),as.matrix(mal_data[,'Malicious']), alpha = 1)
  
  final_lambda_lse <- final_model$lambda.1se
  
  probs <- predict(final_model,newx = as.matrix(family_mal_data[,-c(1)]),s=final_lambda_lse,type="response")
  
  preds <- rep(0,nrow(probs))
  preds[probs>thresh] <- 1
  
  # Create confusion matrix
  cnfMatrix <- confusionMatrix(preds, as.factor(family_mal_data[,'Malicious']))
  
  # Calculate AUC values
  roccurve <- pROC::roc(family_mal_data[,'Malicious'] ~ as.vector(probs))#
  #plot(roccurve)  
  auc_value <- pROC::auc(roccurve)
  
  # # Create ROC plots using ROCR package
  # roc_pred <- ROCR::prediction( as.vector(probs), family_mal_data[,'Malicious'] )
  # roc_perf <- ROCR::performance( roc_pred, "tpr", "fpr" )
  # 
  # # Create ROC plots for Miuref and Bunitu
  # if(family_nm=='Miuref'){
  #   plot( roc_perf, col = "black", lty=3)
  #   legend("topright", c(family_nm), lty=3, 
  #          col = "black", bty="n", inset=c(0,0.2))
  #   
  # } 
  # if(family_nm=='Bunitu'){
  #   plot( roc_perf, add = TRUE, col= "black", lty=5)
  #   legend("topright", c(family_nm), lty=5, 
  #          col = "black", bty="n", inset=c(0,0.3))
  #   
  # } 
  
  return(list(cnfMatrix$byClass['Balanced Accuracy'][1],cnfMatrix$byClass['Precision'],
              cnfMatrix$byClass['Recall'],cnfMatrix$byClass['F1'],
              auc_value))
}

########################## Perform Leave-One-Bot Out  ##############################
perform_LOO <- function(LOO_datasets, thresh, mtype="lr"){
  if(mtype == "nn"){mtype = "mlpML" }
  mal_data <- LOO_datasets[[1]]
  family_mal_data <- LOO_datasets[[2]]
  
  if(mtype == "lr"){
    # Apply log trnasform to skewed predictors
    mal_data[skewed_columns] <- sapply(mal_data[skewed_columns], function(x) log(x+1))
    family_mal_data[skewed_columns] <- sapply(family_mal_data[skewed_columns], function(x) log(x+1))
    
    # Create final model with LOO as test and all other as train
    final_model <- cv.glmnet(as.matrix(mal_data[,-c(1)]),as.matrix(mal_data[,'Malicious']), alpha = 1)
    final_lambda_lse <- final_model$lambda.1se
    
    #Evaluate model on LOO test data
    probs <- predict(final_model,newx = as.matrix(family_mal_data[,-c(1)]),s=final_lambda_lse,type="response")
    preds <- rep(0,nrow(probs))
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
    
    #Convert response variable to factor for train and test datasets
    mal_data$Malicious <- as.factor(mal_data$Malicious)
    levels(mal_data$Malicious) <- c('Benign','Malicious')
    family_mal_data$Malicious <- as.factor(family_mal_data$Malicious)
    levels(family_mal_data$Malicious) <- c('Benign','Malicious')
    
    #train model
    model <- train(x=mal_data[,-1], y=as.factor(mal_data[,'Malicious']), method = mtype,
                trControl=control,
                preProcess = preProc,
                metric = "ROC",
                tuneLength = 4,
                tuneGrid = mlp_grid)
    #predict on test data and calculate accuracy
    probs <- predict(model,newdata = family_mal_data[,-c(1)], type="prob")
    probs <- probs$Malicious
    
    preds <- rep(0,length(probs))
    preds[probs>thresh] <- 1
    preds <- as.factor(preds)
    levels(preds) <- c('Benign', 'Malicious')
    
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
              auc_value))
}


########################## Implement Leave-One-Out ##############################

# For logistic regreeion, set custom threshold for each family
family_thresh <- c(0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5)
names(family_thresh) <- c('Miuref','Bunitu','Upatre','Dridex','Necurs','Trickbot','Conflicker','Zeus')

# Create empty dataframe loo_df
loo_df <- data.frame(family = character(), balanced_accuracy = integer(), precision = integer(), recall = integer(), F1Score = integer(), auc = integer())

# Iterate through all botnet families one by one and implement Leave-One-Out
for(family_nm in names(family_thresh)){
  loo_datasets <- create_LOO_datasets(all_data = all_data,family_nm = family_nm, thresh=0.5)
  #loo_outcome <- logistic_regr_LOO(loo_datasets, thresh = family_thresh[family_nm])
  loo_outcome <- perform_LOO(loo_datasets, thresh = family_thresh[family_nm], mtype="nn")
  loo_df <- rbind(loo_df, data.frame(family = family_nm, balanced_accuracy = unlist(loo_outcome)[[1]],
                                     precision = unlist(loo_outcome)[[2]] , recall= unlist(loo_outcome)[[3]],
                                     F1Score = unlist(loo_outcome)[[4]], auc = unlist(loo_outcome)[[5]]))
}

print(loo_df)

#Logistic Regression
# family balanced_accuracy precision    recall   F1Score       auc
# 1     Miuref         0.8748175 0.8187461 0.9627737 0.8849379 0.9776413
# 2     Bunitu         0.6972477 0.6244053 0.9900102 0.7658098 0.9211530
# 3     Upatre         0.9729730 0.9816514 0.9639640 0.9727273 0.9918026
# 4     Dridex         0.9661017 0.9661017 0.9661017 0.9661017 0.9959782
# 5     Necurs         0.9799814 0.9990319 0.9608939 0.9795918 0.9989441
# 6   Trickbot         0.9716981 0.9761905 0.9669811 0.9715640 0.9934585
# 7 Conflicker         0.9625000 0.9605809 0.9645833 0.9625780 0.9803646
# 8       Zeus         0.4946889 0.4972635 0.9650986 0.6563467 0.7209687

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

thresh <- 0.5
preds <- rep(0,nrow(probs))
preds[probs>thresh] <- 1

cnfMatrix <- confusionMatrix(preds, as.factor(full_test[,'Malicious']))
cnfMatrix$byClass['Balanced Accuracy'][1]
cnfMatrix$byClass['Precision']
cnfMatrix$byClass['Recall']
cnfMatrix$byClass['F1']