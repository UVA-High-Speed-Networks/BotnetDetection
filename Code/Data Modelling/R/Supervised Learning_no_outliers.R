##################### Libraries #####################
library(randomForest)
library(ranger)
library(plyr)
library(gbm)
library(caret)
library(pROC)
library(tidyverse)
library(plotROC)
library(e1701)

#Parallelization
library(parallel)
library(doParallel)


##################### Reading & Splitting Data #####################
setwd('/Users/babraham/Google Drive/Grad_School/Cyber_Research/Anomaly-based-Intrusion-Detection-System/Data/Traces')
all_data <- read.csv('merged_data_final.csv', header=T) #reading in the data

for(c in colnames(all_data)){
  print(paste(c,length(which(is.na(all_data[,c]))),sep='-'))
}


#get rid of corrupted trace sample
all_data <- all_data[which(all_data$File != "traces_141_1.log.csv"),]
#get rid of index
all_data <- all_data[,-c(1)]

colnames(all_data)[20:29] <- paste("src", colnames(all_data)[20:29], sep = "_")
colnames(all_data)[30:39] <- paste("dest", colnames(all_data)[30:39], sep = "_")

all_data$Malicious <- as.factor(ifelse(all_data$Malicious ==1, "Yes", "No"))
set.seed(134)

#Get rid of outliers (all data < 1% or > 99% quantiles)
all_data_colsub <- all_data[,-c(2:6,38:42)]
outlierlist <- c()
for (c in colnames(all_data_colsub)[-1]){
  mininds <- which(all_data_colsub[,c] < quantile(all_data_colsub[,c], probs=c(.01)))
  maxinds <- which(all_data_colsub[,c] > quantile(all_data_colsub[,c], probs=c(.99)))
  outlierlist <- c(outlierlist, mininds, maxinds)
}
#Get rid of duplicate outlier indices
outlierlist <- unique(outlierlist)
#remove outliers from data
all_data_colsub <- all_data_colsub[-c(outlierlist),]

#Get rid of all useless flag columns (all zeros)
zero_list <- c()
for (c in c(2:length(colnames(all_data_colsub)))){
  if(is.numeric(all_data_colsub[,c])){
    if (sum(all_data_colsub[,c]) == 0){
      zero_list <- c(zero_list, c)
    }
  }
}
all_data_colsub <- all_data_colsub[,-c(zero_list)]


#train_index_old <- sample(1:nrow(all_data_colsub), 16500, replace= FALSE)
train_index <- sample(1:nrow(all_data_colsub), 16500, replace= FALSE)

caret_data <- all_data_colsub[train_index,]
caret_test <- all_data_colsub[-train_index,]

#caret_data_no_pp <- all_data_colsub[train_index_old,]
#caret_test_no_pp <- all_data_colsub[-train_index_old,]

#Normalize Data
cnorm_data <- caret_data
cnorm_test <- caret_test

for(c in colnames(cnorm_data)[-c(1)]){
  cmin = min(cnorm_data[,c(c)])
  cmax = max(cnorm_data[,c(c)])
  cnorm_data[,c] = sapply(cnorm_data[,c], function(x){return(abs(x - cmin)/(cmax - cmin))}) 
}

for(c in colnames(cnorm_test)[-c(1)]){
  cmin = min(cnorm_test[,c(c)])
  cmax = max(cnorm_test[,c(c)])
  cnorm_test[,c] = sapply(cnorm_test[,c], function(x){return(abs(x - cmin)/(cmax - cmin))}) 
}

##################### Data Exploration #####################
library(ggplot2)
#Mean interval Distribution
test1 <- all_data[all_data$mean_intvl<1000,]

plot1 <- ggplot(data = test1,aes(x= Malicious, y=mean_intvl, fill = Malicious)) + geom_boxplot()+
        scale_fill_manual(values=c("green", "red"))+
        theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))

ggplot(data = test2,aes(x= Malicious, y= mean_intvl, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))

boxplot(caret_data$Malicious, caret_data$mean_intvl)


#Mean Source Packets
test2 <- all_data[all_data$mean_src_pkts<100,]

ggplot(data = test2,aes(x= Malicious, y= mean_src_pkts, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))

#Mean Dest Packets
ggplot(data = test4,aes(x= Malicious, y= delta, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))


#Mean Duration
test3 <- all_data[all_data$mean_duration<500,]

plot2 <- ggplot(data = test3,aes(x= Malicious, y= mean_duration, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))+
  stat_summary(fun.y=mean, colour="black", geom="point", shape=18, size=3)+
  geom_text(data = test3, aes(label = Malicious, y = mean_intvl))

#Mean flowct
quantile(all_data$flowct, na.rm=TRUE)
testfc <- all_data[all_data$flowct<36,]

plotfc <- ggplot(data = testfc,aes(x= Malicious, y= flowct, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))+
  stat_summary(fun.y=mean, colour="black", geom="point", shape=18, size=3)+
  geom_text(data = test3, aes(label = Malicious, y = mean_intvl))

grid.arrange(plot1, plot2, ncol=2)

##################### Caret Implementation of Logistic Regression ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE
                        )


lr_norm <- train(as.factor(Malicious) ~., data = cnorm_data, method = "glm",
            family = "binomial",
            trControl=control,
            preProcess = c("BoxCox"),
            metric = "ROC",
            tuneLength = 4)
lr_old <- train(as.factor(Malicious) ~., data = caret_data, method = "glm",
                family = "binomial",
                trControl=control,
                preProcess = c("BoxCox"),
                metric = "ROC",
                tuneLength = 4)

test_pred_lr_norm <- predict(lr, newdata=cnorm_test[,-1])
test_pred_lr_old <- predict(lr_old, newdata=caret_test_old[,-1])

#Confusion Matrices
confusionMatrix(test_pred_lr, cnorm_test[,1])
confusionMatrix(test_pred_lr_old, caret_test[,1])

#ROC
selectedIndices_lr <- rep(TRUE, nrow(caret_data))
l <- ggplot(lr$pred[selectedIndices_lr, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

l + annotate("text", y=0.25, x=0.75,label=paste("LR AUC =", round((calc_auc(l))$AUC, 4)))

calc_auc(l)
###############################
# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  1099   28
# Yes   29  760
# 
# Accuracy : 0.9703          
# 95% CI : (0.9616, 0.9774)
# No Information Rate : 0.5887          
# P-Value [Acc > NIR] : <2e-16          
# 
# Kappa : 0.9386          
# Mcnemar's Test P-Value : 1               
# 
# Sensitivity : 0.9743          
# Specificity : 0.9645          
# Pos Pred Value : 0.9752          
# Neg Pred Value : 0.9632          
# Prevalence : 0.5887          
# Detection Rate : 0.5736          
# Detection Prevalence : 0.5882          
# Balanced Accuracy : 0.9694          
# 
# 'Positive' Class : No  
##################### Caret Implementation of Radial SVM ##################### 
library(caret)
#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(4)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


svm_Radial <- train(as.factor(Malicious) ~., data = caret_data, method = "svmRadial",
                    trControl=control,
                    preProcess = c("center"),
                    metric = "ROC",
                    tuneLength = 10, 
                    na_action=na.exclude)

print(svm_Radial)

# Select a parameter setting
selectedIndices_svm <- svm_Radial$pred$C == 128

g <- ggplot(svm_Radial$pred[selectedIndices_svm, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

g + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(g))$AUC, 4)))


#test
test_pred_svmr <- predict(svm_Radial, newdata = caret_test[,-1])
confusionMatrix(test_pred_svmr, as.factor(caret_test[,1]))

##################### SVM-R Results #####################
# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  1119   17
# Yes    9  771
# 
# Accuracy : 0.9864          
# 95% CI : (0.9802, 0.9911)
# No Information Rate : 0.5887          
# P-Value [Acc > NIR] : <2e-16          
# 
# Kappa : 0.9719          
# Mcnemar's Test P-Value : 0.1698          
# 
# Sensitivity : 0.9920          
# Specificity : 0.9784          
# Pos Pred Value : 0.9850          
# Neg Pred Value : 0.9885          
# Prevalence : 0.5887          
# Detection Rate : 0.5840          
# Detection Prevalence : 0.5929          
# Balanced Accuracy : 0.9852          
# 
# 'Positive' Class : No
##################### Caret Implementation of Random Forest ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


rf <- train(as.factor(Malicious) ~., data = caret_data, method = "rf",
                    trControl=control,
                    preProcess = c("center"),
                    metric = "ROC",
                    tuneLength = 4)

print(rf)

# Select a parameter setting
selectedIndices_rf <- rf$pred$mtry == 2

rf$pred$mtry

h <- ggplot(rf$pred[selectedIndices_rf, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

h + annotate("text", y=0.25, x=0.75,label=paste("RF AUC =", round((calc_auc(h))$AUC, 4)))

calc_auc(h)
#test
test_pred_rf <- predict(rf, newdata = caret_test[,-1])
confusionMatrix(test_pred_rf, as.factor(caret_test[,1]))

##################### Random Forest Results #####################
# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  1119    4
# Yes    9  784
# 
# Accuracy : 0.9932          
# 95% CI : (0.9884, 0.9964)
# No Information Rate : 0.5887          
# P-Value [Acc > NIR] : <2e-16          
# 
# Kappa : 0.986           
# Mcnemar's Test P-Value : 0.2673          
# 
# Sensitivity : 0.9920          
# Specificity : 0.9949          
# Pos Pred Value : 0.9964          
# Neg Pred Value : 0.9887          
# Prevalence : 0.5887          
# Detection Rate : 0.5840          
# Detection Prevalence : 0.5861          
# Balanced Accuracy : 0.9935          
# 
# 'Positive' Class : No              


##################### Caret Implementation of Naive Bayes ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


nb <- train(as.factor(Malicious) ~., data = caret_data, method = "nb",
            trControl=control,
            preProcess = c("center"),
            metric = "ROC",
            tuneLength = 10)

print(nb)

# Select a parameter setting
selectedIndices_nb <- which(nb$pred$usekernel == "TRUE" & nb$pred$fL == 0 & nb$pred$adjust == 1)

k <- ggplot(nb$pred[selectedIndices_nb, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

k + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(k))$AUC, 4)))

test_pred_nb <- predict(nb, newdata = caret_test[,-1])
confusionMatrix(test_pred_nb, as.factor(caret_test[,1]))

##################### Naive Bayes Results ##################### 

# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  1028  180
# Yes  100  608
# 
# Accuracy : 0.8539          
# 95% CI : (0.8372, 0.8694)
# No Information Rate : 0.5887          
# P-Value [Acc > NIR] : < 2.2e-16       
# 
# Kappa : 0.6935          
# Mcnemar's Test P-Value : 2.345e-06       
# 
# Sensitivity : 0.9113          
# Specificity : 0.7716          
# Pos Pred Value : 0.8510          
# Neg Pred Value : 0.8588          
# Prevalence : 0.5887          
# Detection Rate : 0.5365          
# Detection Prevalence : 0.6305          
# Balanced Accuracy : 0.8415          
# 
# 'Positive' Class : No              

###################### Importance plots ###################

#First run to check variable importance
set.seed(12)
rf1 <- randomForest(all_data_colsub[,-c(1)], all_data_colsub[,1], mtry = 2, ntree = 300, importance = T)
var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")

#Asthetic changes to importance plot
imp <- data.frame((rf1$importance)[,4])

imp <- imp %>% rownames_to_column(var="Variables") %>% remove_rownames
colnames(imp)[2] <-  "MeanGiniDecrease"
imp <- imp[order(-imp$MeanGiniDecrease),][1:25,]

plot3 <- ggplot(imp) + geom_point(aes(x = MeanGiniDecrease,y = reorder(Variables, MeanGiniDecrease)), size = 5, color = "sienna2")+
  ylab("Variables") + 
  theme(panel.background = element_rect(fill = 'grey93'),
        axis.text=element_text(size=12, face = "bold",color = "grey18"),
        axis.title=element_text(size=20,face="bold",color = "grey18"),
        plot.background = element_rect(fill = "grey93"))
#Get rf1 preds
test_pred_rf1 <- predict(rf1, newdata = caret_test[,-1])
confusionMatrix(test_pred_rf1, as.factor(caret_test[,1]))


###################### ROC plots ###################

rf_preds <- rf$pred[selectedIndices_rf, ]
svm_preds <- svm_Radial$pred[selectedIndices_svm, ]
nb_preds <- nb$pred[selectedIndices_nb, ]
lr_preds <- lr.df

#Select only relevant columns
rf_no_preds <- rf_preds[, c(2,4,5)]
svm_no_preds <- svm_preds[, c(2,4,5)]
nb_no_preds <- nb_preds[, c(2,4,5)]
lr_no_preds <- lr_preds[, c(1,3,4)]

#Rename probablilites column to identify model
colnames(rf_no_preds)[2] <- "Random Forest"
colnames(svm_no_preds)[2] <- "Radial SVM"
colnames(nb_no_preds)[2] <- "Naive Bayes"
colnames(lr_no_preds)[1] <- "Logistic Regression"


#Merge probabilities
all_preds <- Reduce(function(dtf1, dtf2) merge(dtf1, dtf2, by = c("obs", "rowIndex"), all = TRUE),list(rf_no_preds,svm_no_preds, nb_no_preds, lr_no_preds))

########### With Naive Bayes ###################
#Melt into longform for vizualization
longtest <- melt_roc(all_preds, "obs", c("Random Forest", "Radial SVM", "Naive Bayes", "Logistic Regression"))

#Plot
combined_roc <- ggplot(longtest, aes(d = D, m = M, color = name )) + geom_roc(n.cuts = F, size = 2)
  
plot4 <- combined_roc+ annotate("text", y=0.13, x=0.74,color = "grey93",size = 8,label=paste("LR AUC =", round((calc_auc(l))$AUC, 4)))+
              annotate("text", y=0.18, x=0.74,color = "grey93",size = 8,label=paste("NB AUC =", round((calc_auc(k))$AUC, 4)))+
              annotate("text", y=0.23, x=0.75,color = "grey93",size = 8,label=paste("SVM AUC =", round((calc_auc(g))$AUC, 4)))+
              annotate("text", y=0.28, x=0.74,color = "grey93",size = 8,label=paste("RF AUC =",round((calc_auc(h))$AUC, 4)))+
              theme(panel.background = element_rect(fill = 'grey18'),
              axis.text=element_text(size=12, face = "bold",color = "grey93"),
              axis.title=element_text(size=20,face="bold",color = "grey93"),
              plot.background = element_rect(fill = "grey18"))

########### Without Naive Bayes ###################
#Melt into longform for vizualization
longtest <- melt_roc(all_preds, "obs", c("Random Forest", "Radial SVM", "Logistic Regression"))
#Plot
combined_roc <- ggplot(longtest, aes(d = D, m = M, color = name )) + geom_roc(n.cuts = F, size = 2)

plot4 <- combined_roc+ annotate("text", y=0.18, x=0.74,color = "grey93",size = 8,label=paste("LR AUC =", round((calc_auc(l))$AUC, 4)))+
  annotate("text", y=0.23, x=0.75,color = "grey93",size = 8,label=paste("SVM AUC =", round((calc_auc(g))$AUC, 4)))+
  annotate("text", y=0.28, x=0.74,color = "grey93",size = 8,label=paste("RF AUC =",round((calc_auc(h))$AUC, 4)))+
  theme(panel.background = element_rect(fill = 'grey18'),
        axis.text=element_text(size=12, face = "bold",color = "grey93"),
        axis.title=element_text(size=20,face="bold",color = "grey93"),
        plot.background = element_rect(fill = "grey18"))
plot4

grid.arrange(plot1, plot2, ncol=2)
